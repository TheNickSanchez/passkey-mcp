"""Keychain CRUD operations for passkey entries.

Secrets live in the OS keychain (one keychain item per entry). The entry
*index* — secret-free v2 metadata (key names, timestamps, cached policy) —
lives in a plain file (``entries.json`` in the data dir) with atomic
``0o600`` writes, guarded by a PID-aware lock file. Older versions stored
either a v1 ``list[str]`` in ``entries.json`` or ``__entries__`` in the
keychain; both upgrade seamlessly without eager N+1 Keychain reads.
"""

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from .audit import log_operation
from .dirs import ensure_data_dir, get_data_dir
from .models import RESERVED_NAMES, VALID_POLICIES, Entry, EntryMeta

SERVICE = "passkey"
METADATA_KEY = "__entries__"  # legacy keychain-held index (migrated to file)
POLICY_HMAC_KEY_NAME = "__policy_hmac_key__"
INDEX_VERSION = 2
POLICY_STORE_VERSION = 1
POLICY_ANCHOR_VERSION = "pk_policy_v1"
_EMPTY_POLICIES_SHA256 = hashlib.sha256(b"{}").hexdigest()

# --- Concurrency Lock ---
LOCK_TIMEOUT = 10  # seconds


def _get_lock_file() -> Path:
    return get_data_dir() / "metadata.lock"


def _get_index_path() -> Path:
    return get_data_dir() / "entries.json"


def get_policies_path() -> Path:
    """Return path to <data_dir>/policies.json."""
    return get_data_dir() / "policies.json"


def _fallback_policy_key_path() -> Path:
    return ensure_data_dir() / ".policy_hmac_key"


def _policy_marker_path() -> Path:
    return get_data_dir() / ".policies_initialized"


def is_policy_store_initialized() -> bool:
    """Return True if policies.json exists or was previously initialized in data_dir."""
    return get_policies_path().exists() or _policy_marker_path().exists()


def _is_process_alive(pid: int) -> bool:
    """Cross-platform process existence check."""
    if sys.platform == "win32":
        try:
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if not handle:
                return False
            exit_code = ctypes.c_ulong(0)
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return exit_code.value == 259  # STILL_ACTIVE
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists but no permission


def _is_lock_stale() -> bool:
    """Check if an existing lock file was left by a dead process."""
    lock_file = _get_lock_file()
    try:
        pid_str = lock_file.read_text().strip()
        pid = int(pid_str)
        return not _is_process_alive(pid)
    except (ValueError, OSError):
        return True


@contextlib.contextmanager
def _metadata_lock():
    """Context manager for a PID-aware file lock to prevent index race conditions."""
    lock_file = _get_lock_file()
    ensure_data_dir()
    start_time = time.monotonic()

    while True:
        try:
            fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            break
        except FileExistsError:
            if _is_lock_stale():
                with contextlib.suppress(OSError):
                    os.remove(lock_file)
                continue
            if time.monotonic() - start_time > LOCK_TIMEOUT:
                raise KeychainAccessError(
                    f"Could not acquire metadata lock after {LOCK_TIMEOUT}s. "
                    f"Lock held by another process. Lock file: {lock_file}"
                ) from None
            time.sleep(0.1)

    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            os.remove(lock_file)


class PasskeyError(Exception):
    """Base exception for passkey errors with structured agent metadata."""

    exit_code: int = 1
    default_error_code: str = "PASSKEY_ERROR"

    def __init__(
        self,
        message: str = "",
        *,
        error_code: str | None = None,
        entry: str | None = None,
        missing_fields: list[str] | None = None,
        remediation_command: str | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code: str = error_code or self.default_error_code
        self.entry: str | None = entry
        self.missing_fields: list[str] = list(missing_fields) if missing_fields else []
        self.remediation_command: str | None = remediation_command

    def to_error_dict(self) -> dict[str, object]:
        """Serialize structured error envelope (guaranteed free of secret values)."""
        payload: dict[str, object] = {
            "ok": False,
            "error_code": self.error_code,
            "message": str(self),
        }
        if self.entry is not None:
            payload["entry"] = self.entry
        if self.missing_fields:
            payload["missing_fields"] = list(self.missing_fields)
        if self.remediation_command is not None:
            payload["remediation_command"] = self.remediation_command
        return payload


class KeychainAccessError(PasskeyError):
    """Raised when Keychain access fails."""

    default_error_code: str = "KEYCHAIN_ACCESS_ERROR"


class EntryCorruptedError(PasskeyError):
    """Raised when entry data cannot be parsed."""

    default_error_code: str = "ENTRY_CORRUPTED"


def _keyring_error_message(e: Exception) -> str:
    """Build a platform-appropriate error message for keyring failures."""
    if sys.platform == "linux":
        return (
            f"Failed to access the system keyring. On Linux, a running and unlocked "
            f"keyring daemon (e.g. GNOME Keyring or KWallet) is required. "
            f"In headless/SSH environments, set PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring "
            f"and use the export/import commands for secret management instead. Error: {e}"
        )
    if sys.platform == "win32":
        return (
            f"Failed to access Windows Credential Manager. "
            f"Ensure your Windows user session is active. Error: {e}"
        )
    return (
        f"Failed to access Keychain. Ensure Python has Keychain access. "
        f"Check System Settings > Privacy & Security. Error: {e}"
    )


# --- HMAC-Anchored Policy Store (policies.json + single __policy_hmac_key__) ---


def _canonical_policies_bytes(policies_map: dict[str, str]) -> bytes:
    return json.dumps(policies_map, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse_policy_anchor_json(raw_text: str) -> dict | None:
    """Parse a 'pk_policy_v1' anchor JSON string; return None for non-anchor values."""
    try:
        parsed = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict) or parsed.get("v") != POLICY_ANCHOR_VERSION:
        return None
    key_hex = parsed.get("k")
    digest = parsed.get("digest")
    count = parsed.get("count")
    if (
        not isinstance(key_hex, str)
        or len(key_hex) < 64
        or not isinstance(digest, str)
        or len(digest) != 64
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
    ):
        raise PasskeyError(
            "Policy store integrity check failed: malformed Keychain policy anchor.",
            error_code="POLICY_STORE_TAMPERED",
        )
    try:
        bytes.fromhex(key_hex)
        bytes.fromhex(digest)
    except ValueError as e:
        raise PasskeyError(
            "Policy store integrity check failed: invalid hex in Keychain policy anchor.",
            error_code="POLICY_STORE_TAMPERED",
        ) from e
    return parsed


def _read_policy_anchor(*, policies_file_exists: bool) -> dict | None:
    """Read 'pk_policy_v1' anchor from Keychain (with .policy_hmac_key fallback on KeyringError)."""
    try:
        stored = keyring.get_password(SERVICE, POLICY_HMAC_KEY_NAME)
        if isinstance(stored, str) and stored.strip():
            parsed = _parse_policy_anchor_json(stored.strip())
            if parsed is not None:
                return parsed
        if not policies_file_exists:
            return None
        raise PasskeyError(
            "Policy store integrity check failed: missing or invalid Keychain anchor for policies.json.",
            error_code="POLICY_STORE_TAMPERED",
        )
    except KeyringError as e:
        fb_path = _fallback_policy_key_path()
        if fb_path.exists():
            try:
                fb_parsed = _parse_policy_anchor_json(fb_path.read_text(encoding="utf-8").strip())
            except OSError:
                fb_parsed = None
            if fb_parsed is not None:
                return fb_parsed
        if policies_file_exists:
            raise KeychainAccessError(
                f"Failed to access Keychain to verify policies.json: {e}"
            ) from e
        return None


def _load_policy_store_with_key_nolock() -> tuple[dict[str, str], str | None]:
    """Load and verify policies.json against __policy_hmac_key__, returning (policies_map, key_hex)."""
    path = get_policies_path()
    exists = path.exists()
    anchor = _read_policy_anchor(policies_file_exists=exists)
    if not exists:
        if anchor is not None and (
            anchor["count"] > 0 or anchor["digest"] != _EMPTY_POLICIES_SHA256
        ):
            raise PasskeyError(
                "Policy store integrity check failed: policies.json is missing while Keychain "
                "anchor records active policies (deletion detected).",
                error_code="POLICY_STORE_TAMPERED",
            )
        return {}, (anchor["k"] if anchor is not None else None)

    assert anchor is not None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise PasskeyError(
            f"Policy store is corrupted or unreadable: {e}",
            error_code="POLICY_STORE_TAMPERED",
        ) from e

    if not isinstance(raw, dict):
        raise PasskeyError(
            "Policy store integrity check failed: invalid structure.",
            error_code="POLICY_STORE_TAMPERED",
        )

    raw_policies = raw.get("policies")
    stored_hmac = raw.get("hmac")
    if (
        raw.get("version") != POLICY_STORE_VERSION
        or not isinstance(raw_policies, dict)
        or not isinstance(stored_hmac, str)
    ):
        raise PasskeyError(
            "Policy store integrity check failed: missing policies payload or HMAC signature.",
            error_code="POLICY_STORE_TAMPERED",
        )

    policies_map: dict[str, str] = {}
    for k, v in raw_policies.items():
        if not isinstance(k, str) or not isinstance(v, str) or v not in VALID_POLICIES:
            raise PasskeyError(
                f"Policy store integrity check failed: invalid policy entry for {k!r}.",
                error_code="POLICY_STORE_TAMPERED",
            )
        policies_map[k] = v

    canonical = _canonical_policies_bytes(policies_map)
    key_bytes = bytes.fromhex(anchor["k"])
    expected_hmac = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(stored_hmac, expected_hmac):
        raise PasskeyError(
            "Policy store integrity check failed: policies.json HMAC mismatch (tampering detected).",
            error_code="POLICY_STORE_TAMPERED",
        )

    actual_digest = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(actual_digest, anchor["digest"]) or len(policies_map) != anchor["count"]:
        raise PasskeyError(
            "Policy store integrity check failed: policies.json digest mismatch against "
            "Keychain anchor (rollback/replay detected).",
            error_code="POLICY_STORE_TAMPERED",
        )

    return policies_map, anchor["k"]


def verify_policy_store() -> dict[str, str]:
    """Verify <data_dir>/policies.json against __policy_hmac_key__ and return policies map."""
    policies_map, _ = _load_policy_store_with_key_nolock()
    return policies_map


def _save_policy_store_nolock(
    policies_map: dict[str, str],
    *,
    key_hex: str | None = None,
) -> None:
    """Atomically write policies.json (0o600) and update __policy_hmac_key__ anchor."""
    ensure_data_dir()
    effective_key_hex = key_hex or secrets.token_hex(32)
    canonical = _canonical_policies_bytes(policies_map)
    digest = hashlib.sha256(canonical).hexdigest()
    count = len(policies_map)
    mac = hmac.new(bytes.fromhex(effective_key_hex), canonical, hashlib.sha256).hexdigest()

    anchor_str = json.dumps(
        {
            "v": POLICY_ANCHOR_VERSION,
            "k": effective_key_hex,
            "digest": digest,
            "count": count,
        },
        separators=(",", ":"),
    )

    path = get_policies_path()
    try:
        keyring.set_password(SERVICE, POLICY_HMAC_KEY_NAME, anchor_str)
    except KeyringError as e:
        fb_path = _fallback_policy_key_path()
        if path.exists() and not fb_path.exists():
            raise KeychainAccessError(
                f"Failed to access Keychain to update policies.json: {e}"
            ) from e
        fd_fb, tmp_fb = tempfile.mkstemp(dir=fb_path.parent, prefix=".polkey-", suffix=".tmp")
        try:
            with os.fdopen(fd_fb, "w", encoding="utf-8") as f:
                f.write(anchor_str + "\n")
            os.chmod(tmp_fb, 0o600)
            os.replace(tmp_fb, fb_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_fb)
            raise

    payload = {
        "version": POLICY_STORE_VERSION,
        "policies": {k: policies_map[k] for k in sorted(policies_map)},
        "hmac": mac,
    }
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".policies-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, indent=2) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise

    marker = _policy_marker_path()
    if not marker.exists():
        with contextlib.suppress(OSError):
            fd_m = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd_m)


# --- Entry index (file-based v2 metadata, atomic 0o600 writes) ---


def _parse_meta_row(name: str, raw: object, path: Path) -> EntryMeta:
    """Validate and parse a single entries.json v2 metadata row."""
    if not isinstance(raw, dict):
        raise EntryCorruptedError(
            f"Entry index is corrupted (invalid metadata row for '{name}'): '{path}'"
        )
    raw_fields = raw.get("fields", [])
    raw_cfg = raw.get("config_keys", [])
    raw_policy = raw.get("policy", "allow")
    hydrated = raw.get("hydrated", True)
    if (
        not isinstance(raw_fields, list)
        or not all(isinstance(x, str) for x in raw_fields)
        or not isinstance(raw_cfg, list)
        or not all(isinstance(x, str) for x in raw_cfg)
        or not isinstance(raw_policy, str)
        or not isinstance(hydrated, bool)
    ):
        raise EntryCorruptedError(
            f"Entry index is corrupted (malformed field types for '{name}'): '{path}'"
        )
    for opt_key in ("created", "modified", "last_rotated", "source"):
        val = raw.get(opt_key)
        if val is not None and not isinstance(val, str):
            raise EntryCorruptedError(
                f"Entry index is corrupted (invalid '{opt_key}' for '{name}'): '{path}'"
            )

    policy = raw_policy if raw_policy in VALID_POLICIES else "allow"
    return EntryMeta(
        name=name,
        fields=list(raw_fields),
        config_keys=list(raw_cfg),
        policy=policy,
        created=raw.get("created"),
        modified=raw.get("modified"),
        last_rotated=raw.get("last_rotated"),
        source=raw.get("source"),
        hydrated=hydrated,
    )


def _write_index_nolock(meta_map: dict[str, EntryMeta]) -> None:
    """Atomically write the v2 entry metadata index (temp file + os.replace, 0o600)."""
    path = _get_index_path()
    ensure_data_dir()
    payload = {
        "version": INDEX_VERSION,
        "entries": {name: meta_map[name].to_index_dict() for name in sorted(meta_map)},
    }
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".entries-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, indent=2) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _migrate_legacy_index() -> dict[str, EntryMeta]:
    """One-time migration: move the keychain-held ``__entries__`` index to entries.json v2."""
    try:
        legacy = keyring.get_password(SERVICE, METADATA_KEY)
    except KeyringError as e:
        raise KeychainAccessError(_keyring_error_message(e)) from e
    if not legacy:
        return {}
    try:
        names = json.loads(legacy)
    except json.JSONDecodeError as e:
        raise EntryCorruptedError(
            f"Entry metadata is corrupted. Consider deleting '{METADATA_KEY}' "
            f"from Keychain Access app and re-creating entries. Error: {e}"
        ) from e
    if not isinstance(names, list) or not all(isinstance(x, str) for x in names):
        raise EntryCorruptedError(
            f"Entry metadata '{METADATA_KEY}' is corrupted (expected list of strings)."
        )
    meta_map = {name: EntryMeta(name=name, hydrated=False) for name in sorted(names)}
    _write_index_nolock(meta_map)
    with contextlib.suppress(Exception):
        keyring.delete_password(SERVICE, METADATA_KEY)
    log_operation("metadata_migration", details={"count": len(meta_map), "format": "file-index-v2"})
    return meta_map


def _read_index_nolock() -> dict[str, EntryMeta]:
    """Read the entry index file (accepting both legacy v1 list and v2 metadata dict)."""
    path = _get_index_path()
    if not path.exists():
        return _migrate_legacy_index()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise EntryCorruptedError(
            f"Entry index is corrupted. Fix or delete '{path}'. Error: {e}"
        ) from e

    # Legacy v1 format: ["entry1", "entry2"] -> unhydrated EntryMeta with 0 Keychain calls
    if isinstance(data, list):
        if not all(isinstance(x, str) for x in data):
            raise EntryCorruptedError(f"Entry index is corrupted (invalid v1 list): '{path}'")
        return {name: EntryMeta(name=name, hydrated=False) for name in data}

    # Current v2 format: {"version": 2, "entries": {"<name>": {...}}}
    if isinstance(data, dict):
        if data.get("version") != INDEX_VERSION or not isinstance(data.get("entries"), dict):
            raise EntryCorruptedError(
                f"Entry index is corrupted (invalid v2 structure): '{path}'"
            )
        meta_map: dict[str, EntryMeta] = {}
        for ename, raw_meta in data["entries"].items():
            if not isinstance(ename, str):
                raise EntryCorruptedError(f"Entry index is corrupted: '{path}'")
            meta_map[ename] = _parse_meta_row(ename, raw_meta, path)
        return meta_map

    raise EntryCorruptedError(f"Entry index is corrupted: '{path}'")


def list_entries() -> list[str]:
    """Get sorted list of all stored entry names with 0 Keychain reads.

    This function is thread-safe and acquires a lock.

    Returns:
        Sorted list of entry names, empty list if none exist.

    Raises:
        KeychainAccessError: If Keychain access fails during legacy migration.
        EntryCorruptedError: If the entry index is corrupted.
    """
    with _metadata_lock():
        return sorted(_read_index_nolock().keys())


def save_entry(entry: Entry, is_update: bool = False) -> None:
    """Save entry to Keychain and atomically update secret-free v2 metadata in entries.json.

    Args:
        entry: The Entry to save
        is_update: If True, this is an update to existing entry

    Raises:
        KeychainAccessError: If Keychain access fails.
    """
    try:
        # Update modified timestamp
        entry.touch()

        # Set the password for the entry itself (outside the lock)
        keyring.set_password(SERVICE, entry.name, entry.to_json())

        # Atomically persist hydrated v2 metadata (and sync policies.json if initialized)
        with _metadata_lock():
            if is_policy_store_initialized():
                policies_map, pol_key = _load_policy_store_with_key_nolock()
                if policies_map.get(entry.name) != entry.policy:
                    policies_map[entry.name] = entry.policy
                    _save_policy_store_nolock(policies_map, key_hex=pol_key)
            meta_map = _read_index_nolock()
            is_new = entry.name not in meta_map
            meta_map[entry.name] = EntryMeta.from_entry(entry)
            _write_index_nolock(meta_map)

        # Audit log: label by what actually happened, not the caller's hint
        log_operation(
            operation="create" if is_new else "update",
            entry_name=entry.name,
            details={
                "field_count": len(entry.fields),
                "source": entry.source or "manual",
            },
        )
    except KeyringError as e:
        log_operation("save", entry.name, {"error": str(e)}, success=False)
        raise KeychainAccessError(f"Failed to save '{entry.name}': {e}") from e


def _backfill_entry_meta(entry: Entry) -> None:
    """Best-effort lazy hydration and drift repair of entries.json v2 metadata."""
    fresh = EntryMeta.from_entry(entry)
    with contextlib.suppress(Exception), _metadata_lock():
        meta_map = _read_index_nolock()
        existing = meta_map.get(entry.name)
        if existing != fresh:
            meta_map[entry.name] = fresh
            _write_index_nolock(meta_map)


def _get_entry(name: str, *, log_read: bool) -> Entry | None:
    """Retrieve entry from Keychain by name (internal; read logging optional)."""
    if name in RESERVED_NAMES:
        raise PasskeyError(f"'{name}' is a reserved internal key")
    try:
        # This operation is atomic and does not need the metadata lock
        data = keyring.get_password(SERVICE, name)
        if not data:
            # Empty/None can mean a locked or transient keychain, not a
            # deleted entry. Leave the name in entries.json.
            return None

        entry = Entry.from_json(name, data)
        if is_policy_store_initialized():
            policies_map = verify_policy_store()
            if name in policies_map:
                entry.policy = policies_map[name]
        _backfill_entry_meta(entry)
        if log_read:
            log_operation("read", name)
        return entry
    except KeyringError as e:
        if log_read:
            log_operation("read", name, {"error": str(e)}, success=False)
        raise KeychainAccessError(_keyring_error_message(e)) from e
    except json.JSONDecodeError as e:
        if log_read:
            log_operation("read", name, {"error": "corrupted"}, success=False)
        raise EntryCorruptedError(
            f"Entry '{name}' is corrupted. Delete and recreate it. Error: {e}"
        ) from e


def get_entry(name: str) -> Entry | None:
    """Retrieve entry from Keychain by name.

    Args:
        name: The entry identifier

    Returns:
        Entry if found, None otherwise.

    Raises:
        KeychainAccessError: If Keychain access fails.
        EntryCorruptedError: If entry data is corrupted.
    """
    return _get_entry(name, log_read=True)


def get_entry_meta(name: str, *, hydrate: bool = True) -> EntryMeta | None:
    """Retrieve secret-free EntryMeta from entries.json (0 Keychain calls when hydrated)."""
    if name in RESERVED_NAMES:
        raise PasskeyError(f"'{name}' is a reserved internal key")

    with _metadata_lock():
        meta_map = _read_index_nolock()
        meta = meta_map.get(name)

    if meta is None:
        return None
    if meta.hydrated or not hydrate:
        return meta

    # Lazy one-time hydration for legacy v1 index entries
    entry = _get_entry(name, log_read=False)
    if entry is None:
        return None
    return EntryMeta.from_entry(entry)


def get_all_entry_metas(*, hydrate_unmigrated: bool = False) -> list[EntryMeta]:
    """Return sorted EntryMeta list from entries.json (0 Keychain calls when hydrated)."""
    with _metadata_lock():
        meta_map = _read_index_nolock()

    if not hydrate_unmigrated:
        return [meta_map[k] for k in sorted(meta_map)]

    results: list[EntryMeta] = []
    for name in sorted(meta_map):
        meta = meta_map[name]
        if meta.hydrated:
            results.append(meta)
        else:
            entry = _get_entry(name, log_read=False)
            if entry is not None:
                results.append(EntryMeta.from_entry(entry))
    return results


def delete_entry(name: str) -> bool:
    """Delete entry from Keychain and remove its metadata row from entries.json.

    Args:
        name: The entry identifier to delete

    Returns:
        True if deleted, False if entry didn't exist.

    Raises:
        KeychainAccessError: If Keychain access fails.
    """
    deleted = False
    try:
        # First, delete the entry itself (no lock needed for this part)
        keyring.delete_password(SERVICE, name)
        deleted = True
    except PasswordDeleteError:
        # The password to delete was not found, so it's already gone.
        # We should still proceed to ensure the index is clean.
        deleted = False  # It wasn't "deleted" just now
    except KeyringError as e:
        log_operation("delete", name, {"error": str(e)}, success=False)
        raise KeychainAccessError(f"Failed to delete '{name}': {e}") from e

    # Update the index (and policies.json if initialized) atomically
    try:
        with _metadata_lock():
            if is_policy_store_initialized():
                policies_map, pol_key = _load_policy_store_with_key_nolock()
                if name in policies_map:
                    del policies_map[name]
                    _save_policy_store_nolock(policies_map, key_hex=pol_key)
            meta_map = _read_index_nolock()
            if name in meta_map:
                del meta_map[name]
                _write_index_nolock(meta_map)
                deleted = True
            elif deleted:
                # We deleted a password but it wasn't in our index.
                log_operation("delete_dangling", name)
    except KeyringError as e:
        log_operation("delete", name, {"error": str(e)}, success=False)
        raise KeychainAccessError(f"Failed to update index after deleting '{name}': {e}") from e

    if deleted:
        log_operation("delete", name)
    return deleted


def rename_entry(old_name: str, new_entry: Entry) -> None:
    """Rename an entry by saving under a new name and deleting the old one.

    Args:
        old_name: The current entry name to delete after saving.
        new_entry: Entry object with the new name and updated fields.

    Raises:
        KeychainAccessError: If Keychain access fails.
        PasskeyError: If new_name already exists.
    """
    with _metadata_lock():
        existing = _read_index_nolock()
        if new_entry.name != old_name and new_entry.name in existing:
            raise PasskeyError(f"Entry '{new_entry.name}' already exists.")

    # Save new entry
    save_entry(new_entry, is_update=(new_entry.name == old_name))

    # Delete old entry if name changed
    if new_entry.name != old_name:
        delete_entry(old_name)
        log_operation("rename", old_name, details={"new_name": new_entry.name})


def get_all_entries(*, log_read: bool = True) -> list[Entry]:
    """Get all entries with full data from the OS Keychain.

    Reads every entry without logging a per-entry "read" (a single bulk read
    is logged when ``log_read`` is True). Discovery and preflight paths
    should call ``get_all_entry_metas()`` instead.

    Returns:
        List of all Entry objects.

    Raises:
        KeychainAccessError: If Keychain access fails.
    """
    names = list_entries()
    entries = []

    for name in names:
        entry = _get_entry(name, log_read=False)
        if entry:
            entries.append(entry)

    if entries and log_read:
        log_operation("read", details={"bulk": True, "count": len(entries)})

    return entries


def set_entry_policy(name: str, policy: str) -> EntryMeta:
    """Update a single entry's policy in policies.json + entries.json v2 with 0 secret Keychain touches."""
    if name in RESERVED_NAMES:
        raise PasskeyError(f"'{name}' is a reserved internal key")
    if policy not in VALID_POLICIES:
        raise PasskeyError(
            f"Invalid policy '{policy}'. Expected one of: {', '.join(sorted(VALID_POLICIES))}",
            error_code="INVALID_USAGE",
        )

    with _metadata_lock():
        meta_map = _read_index_nolock()
        if name not in meta_map:
            raise PasskeyError(
                f"Entry '{name}' not found",
                error_code="ENTRY_NOT_FOUND",
                entry=name,
            )
        try:
            policies_map, pol_key = _load_policy_store_with_key_nolock()
        except PasskeyError as e:
            if e.error_code == "POLICY_STORE_TAMPERED":
                raise PasskeyError(
                    f"{e} Run 'passkey policy --all <session|prompt|allow>' in your terminal "
                    "to re-authenticate and rebuild policies.json.",
                    error_code="POLICY_STORE_TAMPERED",
                    entry=name,
                    remediation_command="passkey policy --all session",
                ) from e
            raise
        policies_map[name] = policy
        _save_policy_store_nolock(policies_map, key_hex=pol_key)

        meta = meta_map[name]
        meta.policy = policy
        if meta.hydrated:
            meta.modified = datetime.now().isoformat()
        _write_index_nolock(meta_map)
        return meta


def bulk_update_policies(
    entry_names: list[str],
    policy: str,
    *,
    reanchor: bool = False,
) -> tuple[list[str], list[str]]:
    """Update access policy across multiple entries in O(1) without touching secret Keychain items.

    Updates <data_dir>/policies.json + __policy_hmac_key__ + entries.json v2 in one lock pass,
    preserving hydrated=False on unhydrated rows and full metadata on hydrated rows. When
    ``reanchor=True`` (after OS authentication), rebuilds policies.json cleanly from ``meta_map``
    with a fresh ``pk_policy_v1`` Keychain anchor.

    Returns:
        Tuple of (updated_names, unchanged_names).
    """
    if policy not in VALID_POLICIES:
        raise PasskeyError(
            f"Invalid policy '{policy}'. Expected one of: {', '.join(sorted(VALID_POLICIES))}",
            error_code="INVALID_USAGE",
        )

    updated: list[str] = []
    unchanged: list[str] = []
    now_iso = datetime.now().isoformat()

    with _metadata_lock():
        meta_map = _read_index_nolock()
        if reanchor:
            policies_map = {
                n: (m.policy if m.policy in VALID_POLICIES else "allow")
                for n, m in meta_map.items()
            }
            for name in entry_names:
                meta = meta_map.get(name)
                if meta is None:
                    continue
                policies_map[name] = policy
                meta.policy = policy
                if meta.hydrated:
                    meta.modified = now_iso
                updated.append(name)
            _save_policy_store_nolock(policies_map, key_hex=None)
            _write_index_nolock(meta_map)
            return updated, unchanged

        policies_map, pol_key = _load_policy_store_with_key_nolock()

        for name in entry_names:
            meta = meta_map.get(name)
            if meta is None:
                continue
            has_override = name in policies_map
            current_pol = policies_map[name] if has_override else meta.policy
            if (not meta.hydrated and not has_override) or current_pol != policy:
                policies_map[name] = policy
                meta.policy = policy
                if meta.hydrated:
                    meta.modified = now_iso
                updated.append(name)
            else:
                if meta.policy != policy:
                    meta.policy = policy
                unchanged.append(name)

        if updated or is_policy_store_initialized():
            _save_policy_store_nolock(policies_map, key_hex=pol_key)
            _write_index_nolock(meta_map)

    return updated, unchanged
