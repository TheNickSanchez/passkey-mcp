"""Time- and use-scoped authorization leases authenticated with HMAC-SHA256."""

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import keyring
from keyring.errors import KeyringError

from .audit import detect_actor, log_operation
from .dirs import ensure_data_dir, get_data_dir
from .keychain import PasskeyError, _get_entry
from .models import Entry, is_valid_name

LEASE_HMAC_SERVICE = "passkey"
LEASE_HMAC_KEY_NAME = "__lease_hmac_key__"
MAX_TTL_SECONDS = 7 * 24 * 3600  # 7 days max
_TTL_PATTERN = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_UNIT_MULTIPLIERS = {
    "": 1,
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}


def get_leases_path() -> Path:
    """Return path to <data_dir>/leases.json."""
    return get_data_dir() / "leases.json"


def _fallback_lease_key_path() -> Path:
    return ensure_data_dir() / ".lease_hmac_key"


def _get_or_create_lease_hmac_key() -> bytes:
    """Load or generate 32-byte lease HMAC key in keyring (with 0o600 file fallback)."""
    try:
        stored = keyring.get_password(LEASE_HMAC_SERVICE, LEASE_HMAC_KEY_NAME)
        if stored and len(stored) >= 64:
            return bytes.fromhex(stored.strip())
        new_hex = secrets.token_hex(32)
        keyring.set_password(LEASE_HMAC_SERVICE, LEASE_HMAC_KEY_NAME, new_hex)
        return bytes.fromhex(new_hex)
    except (KeyringError, ValueError):
        key_file = _fallback_lease_key_path()
        if key_file.exists():
            try:
                return bytes.fromhex(key_file.read_text().strip())
            except (OSError, ValueError):
                pass
        new_hex = secrets.token_hex(32)
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(new_hex + "\n")
        return bytes.fromhex(new_hex)


def _compute_leases_hmac(key: bytes, leases_dict: dict) -> str:
    canonical = json.dumps(leases_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def parse_ttl(raw: str | int) -> int:
    """Parse a human TTL string (e.g. '15m', '30s', '2h', '900') into positive seconds."""
    if isinstance(raw, int):
        seconds = raw
    elif isinstance(raw, str):
        match = _TTL_PATTERN.match(raw)
        if not match:
            raise PasskeyError(
                f"Invalid TTL '{raw}'. Expected positive duration like '15m', '30s', '1h', or '900'."
            )
        amount = int(match.group(1))
        unit = match.group(2).lower()
        seconds = amount * _UNIT_MULTIPLIERS[unit]
    else:
        raise PasskeyError(f"Invalid TTL value: {raw!r}")

    if seconds <= 0 or seconds > MAX_TTL_SECONDS:
        raise PasskeyError(
            f"TTL must be between 1s and 7d ({MAX_TTL_SECONDS}s); got {seconds}s."
        )
    return seconds


def _load_leases_store() -> tuple[dict[str, dict], bytes]:
    """Load and verify HMAC of leases.json, returning (leases_map, hmac_key)."""
    key = _get_or_create_lease_hmac_key()
    path = get_leases_path()
    if not path.exists():
        return {}, key

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise PasskeyError(f"Lease store is corrupted or unreadable: {e}") from e

    if not isinstance(raw, dict):
        raise PasskeyError("Lease store integrity check failed: invalid structure")

    leases_map = raw.get("leases")
    stored_hmac = raw.get("hmac")
    if not isinstance(leases_map, dict) or not isinstance(stored_hmac, str):
        raise PasskeyError(
            "Lease store integrity check failed: missing leases payload or HMAC signature"
        )

    expected_hmac = _compute_leases_hmac(key, leases_map)
    if not hmac.compare_digest(stored_hmac, expected_hmac):
        raise PasskeyError(
            "Lease store integrity check failed: leases.json HMAC mismatch (tampering detected)"
        )

    return dict(leases_map), key


def _save_leases_store(leases_map: dict[str, dict], key: bytes) -> None:
    """Atomically write HMAC-signed leases.json with 0o600 permissions."""
    ensure_data_dir()
    path = get_leases_path()
    payload = {
        "version": 1,
        "leases": leases_map,
        "hmac": _compute_leases_hmac(key, leases_map),
    }
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".leases-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, indent=2) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _prune_expired(leases_map: dict[str, dict], now: float) -> bool:
    """Remove expired or zero-remaining-use leases in place; return True if mutated."""
    expired_keys = []
    for name, item in leases_map.items():
        expires_at = float(item.get("expires_at", 0.0))
        rem = item.get("remaining_uses")
        if expires_at <= now or (isinstance(rem, int) and rem <= 0):
            expired_keys.append(name)
    for k in expired_keys:
        del leases_map[k]
    return bool(expired_keys)


def grant_lease(
    entry_name: str,
    *,
    ttl: str | int = "15m",
    max_uses: int | None = None,
    require_biometric: bool = False,
) -> dict:
    """Grant a time- and/or use-scoped lease for entry_name."""
    if not is_valid_name(entry_name):
        raise PasskeyError(f"Invalid entry name '{entry_name}'")

    entry = _get_entry(entry_name, log_read=False)
    if entry is None:
        raise PasskeyError(f"Entry '{entry_name}' not found")

    ttl_seconds = parse_ttl(ttl)
    if max_uses is not None and max_uses <= 0:
        raise PasskeyError("--max-uses must be a positive integer")

    if require_biometric:
        from .auth import require_auth

        require_auth(f"grant lease for '{entry_name}'")

    leases_map, key = _load_leases_store()
    now = time.time()
    _prune_expired(leases_map, now)

    expires_at = now + ttl_seconds
    lease_record = {
        "entry": entry_name,
        "granted_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        "expires_at": expires_at,
        "expires_at_iso": datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat(),
        "ttl_seconds": ttl_seconds,
        "max_uses": max_uses,
        "remaining_uses": max_uses,
        "granted_by": detect_actor().get("client", "terminal"),
    }
    leases_map[entry_name] = lease_record
    _save_leases_store(leases_map, key)

    log_operation(
        "lease_grant",
        entry_name,
        details={"ttl_seconds": ttl_seconds, "max_uses": max_uses},
    )
    return lease_record


def consume_lease(entry_name: str) -> bool:
    """Check and consume 1 use of an active lease for entry_name, if present."""
    leases_map, key = _load_leases_store()
    now = time.time()
    mutated = _prune_expired(leases_map, now)

    lease = leases_map.get(entry_name)
    if lease is None:
        if mutated:
            _save_leases_store(leases_map, key)
        return False

    rem = lease.get("remaining_uses")
    if isinstance(rem, int):
        rem -= 1
        if rem <= 0:
            del leases_map[entry_name]
        else:
            lease["remaining_uses"] = rem
        mutated = True

    if mutated:
        _save_leases_store(leases_map, key)

    log_operation("lease_consume", entry_name)
    return True


def list_leases() -> list[dict]:
    """Return all currently active leases sorted by entry name."""
    leases_map, key = _load_leases_store()
    now = time.time()
    if _prune_expired(leases_map, now):
        _save_leases_store(leases_map, key)
    result = []
    for name in sorted(leases_map):
        item = dict(leases_map[name])
        item["seconds_remaining"] = max(0, int(float(item["expires_at"]) - now))
        result.append(item)
    return result


def revoke_lease(entry_name: str | None = None, *, revoke_all: bool = False) -> int:
    """Revoke a specific lease or all active leases. Returns count revoked."""
    leases_map, key = _load_leases_store()
    now = time.time()
    _prune_expired(leases_map, now)

    if revoke_all:
        count = len(leases_map)
        leases_map.clear()
        _save_leases_store(leases_map, key)
        log_operation("lease_revoke", details={"count": count})
        return count

    if not entry_name:
        raise PasskeyError("Specify an entry name or pass --all to revoke leases.")

    if entry_name in leases_map:
        del leases_map[entry_name]
        _save_leases_store(leases_map, key)
        log_operation("lease_revoke", entry_name, details={"count": 1})
        return 1

    return 0


def authorize_entry_access(entry: Entry, *, operation: str = "inject secrets") -> None:
    """Enforce entry.policy ('allow' vs 'prompt') via active lease or out-of-band OS auth."""
    if getattr(entry, "policy", "allow") != "prompt":
        return

    if consume_lease(entry.name):
        return

    from .auth import authenticate

    approved = authenticate(f"Passkey: authorize '{entry.name}' ({operation})")
    if not approved:
        log_operation("policy_denied", entry.name, success=False)
        raise PasskeyError(
            f"Access denied for prompt-protected entry '{entry.name}'. "
            f"Approve the biometric prompt or run 'passkey lease grant {entry.name}'."
        )

    log_operation("policy_approved", entry.name)
