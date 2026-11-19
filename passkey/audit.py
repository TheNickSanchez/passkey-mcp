"""Tamper-evident HMAC hash-chained audit logging with caller attribution."""

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import keyring
from keyring.errors import KeyringError

from .dirs import ensure_data_dir, get_data_dir

# When the log exceeds this size, the oldest half of the lines is dropped.
MAX_LOG_BYTES = 1_000_000  # ~1 MB
AUDIT_HMAC_SERVICE = "passkey"
AUDIT_HMAC_KEY_NAME = "__audit_hmac_key__"
GENESIS_HMAC = "0" * 64

_AGENT_ENV_MARKERS: tuple[tuple[str, str], ...] = (
    ("CLAUDECODE", "claude-code"),
    ("CLAUDE_CODE_ENTRYPOINT", "claude-code"),
    ("CURSOR_TRACE_ID", "cursor"),
    ("CURSOR_AGENT", "cursor"),
    ("GEMINI_CLI", "gemini-cli"),
    ("CODEX_ENV", "codex"),
    ("OPENAI_CODEX", "codex"),
    ("VSCODE_PID", "vscode"),
)

_KNOWN_AGENT_PROCS = (
    "claude",
    "cursor",
    "gemini",
    "codex",
    "opencode",
    "windsurf",
    "zed",
    "passkey-mcp-server",
)

_SAFE_DETAIL_KEYS = frozenset(
    {
        "bulk",
        "checks",
        "count",
        "created",
        "deep",
        "entries",
        "exposed_count",
        "field_count",
        "fields_injected",
        "format",
        "issues",
        "manifests",
        "max_uses",
        "mode",
        "new_name",
        "no_secrets",
        "origin",
        "policy",
        "read_count",
        "reads_served",
        "resolved_references",
        "scope",
        "skipped",
        "source",
        "trust_status",
        "ttl_seconds",
        "updated",
    }
)

_PPID_CACHE: dict[tuple[int, int], list[dict[str, object]]] = {}


def get_log_path() -> Path:
    """Get the audit log path, creating directory if needed."""
    default = get_data_dir() / "audit.log"
    log_path = Path(os.environ.get("PASSKEY_AUDIT_LOG", default))
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return log_path


def _fallback_hmac_key_path() -> Path:
    return ensure_data_dir() / ".audit_hmac_key"


def _get_or_create_hmac_key() -> bytes:
    """Load or generate the 32-byte audit HMAC key in the OS keyring (with 0o600 file fallback)."""
    try:
        stored = keyring.get_password(AUDIT_HMAC_SERVICE, AUDIT_HMAC_KEY_NAME)
        if stored and len(stored) >= 64:
            return bytes.fromhex(stored.strip())
        new_hex = secrets.token_hex(32)
        keyring.set_password(AUDIT_HMAC_SERVICE, AUDIT_HMAC_KEY_NAME, new_hex)
        return bytes.fromhex(new_hex)
    except (KeyringError, ValueError):
        key_file = _fallback_hmac_key_path()
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


def _canonical_record_bytes(record: dict) -> bytes:
    """Serialize record (excluding 'hmac') deterministically for HMAC signing."""
    signable = {k: v for k, v in record.items() if k != "hmac"}
    return json.dumps(signable, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_hmac(key: bytes, record: dict) -> str:
    return hmac.new(key, _canonical_record_bytes(record), hashlib.sha256).hexdigest()


def _walk_ppid_chain(max_depth: int = 6) -> list[dict[str, object]]:
    """Walk parent PIDs on POSIX to identify invoking CLI/IDE processes."""
    pid = os.getpid()
    ppid = os.getppid()
    cache_key = (pid, ppid)
    if cache_key in _PPID_CACHE:
        return list(_PPID_CACHE[cache_key])

    chain: list[dict[str, object]] = []
    if sys.platform == "win32":
        if ppid > 0:
            chain.append({"pid": ppid, "comm": "unknown"})
        _PPID_CACHE[cache_key] = chain
        return list(chain)

    curr = ppid
    visited: set[int] = {pid}
    for _ in range(max_depth):
        if curr <= 1 or curr in visited:
            break
        visited.add(curr)
        try:
            proc = subprocess.run(
                ["ps", "-o", "ppid=,comm=", "-p", str(curr)],
                capture_output=True,
                text=True,
                timeout=0.5,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                break
            parts = proc.stdout.strip().split(None, 1)
            next_ppid = int(parts[0])
            comm = Path(parts[1].strip()).name if len(parts) > 1 else "unknown"
            chain.append({"pid": curr, "comm": comm})
            curr = next_ppid
        except (ValueError, OSError, subprocess.SubprocessError):
            break

    _PPID_CACHE[cache_key] = chain
    return list(chain)


def detect_actor() -> dict:
    """Detect whether the current invocation originates from an AI agent or human shell."""
    ppid_chain = _walk_ppid_chain()
    detected_client: str | None = None

    for env_var, client_label in _AGENT_ENV_MARKERS:
        if os.environ.get(env_var):
            detected_client = client_label
            break

    if detected_client is None:
        for item in ppid_chain:
            comm_lower = str(item.get("comm", "")).lower()
            for agent_name in _KNOWN_AGENT_PROCS:
                if agent_name in comm_lower:
                    detected_client = agent_name
                    break
            if detected_client:
                break

    actor_type = "agent" if detected_client else "human"
    return {
        "type": actor_type,
        "client": detected_client or "terminal",
        "pid": os.getpid(),
        "ppid_chain": ppid_chain,
    }


def _read_last_hmac(log_path: Path) -> str:
    """Read the HMAC of the last JSONL line in log_path, or GENESIS_HMAC if empty."""
    if not log_path.exists():
        return GENESIS_HMAC
    try:
        lines = [ln.strip() for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        if not lines:
            return GENESIS_HMAC
        last_obj = json.loads(lines[-1])
        if isinstance(last_obj, dict) and isinstance(last_obj.get("hmac"), str):
            return last_obj["hmac"]
    except (OSError, json.JSONDecodeError):
        pass
    return GENESIS_HMAC


def _rotate_if_needed(log_path: Path, hmac_key: bytes) -> None:
    """Atomically cap the log size by dropping the oldest half and re-anchoring HMACs."""
    try:
        if not log_path.exists() or log_path.stat().st_size <= MAX_LOG_BYTES:
            return
        lines = log_path.read_text(encoding="utf-8").splitlines()
        keep_raw = lines[len(lines) // 2 :]

        prev = GENESIS_HMAC
        rebuilt: list[str] = []
        for raw in keep_raw:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                rebuilt.append(stripped + "\n")
                continue

            if isinstance(obj, dict) and "hmac" in obj:
                obj["prev_hmac"] = prev
                obj["hmac"] = _compute_hmac(hmac_key, obj)
                prev = obj["hmac"]
                rebuilt.append(json.dumps(obj) + "\n")
            else:
                rebuilt.append(stripped + "\n")

        fd, tmp_path = tempfile.mkstemp(
            dir=log_path.parent,
            prefix=".audit-rot-",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.writelines(rebuilt)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, log_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
    except OSError:
        pass


def _ensure_secure_permissions(path: Path) -> None:
    """Ensure file has secure permissions (owner only)."""
    if path.exists():
        current_mode = path.stat().st_mode & 0o777
        if current_mode != 0o600:
            path.chmod(0o600)


def log_operation(
    operation: str,
    entry_name: str | None = None,
    details: dict | None = None,
    success: bool = True,
    *,
    argv0: str | None = None,
) -> None:
    """Log an HMAC-chained operation with caller attribution to the audit log."""
    log_path = get_log_path()
    try:
        hmac_key = _get_or_create_hmac_key()
        _rotate_if_needed(log_path, hmac_key)
        prev_hmac = _read_last_hmac(log_path)

        effective_argv0 = (
            Path(argv0).name
            if argv0
            else (Path(sys.argv[0]).name if sys.argv and sys.argv[0] else "passkey")
        )

        record: dict[str, object] = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "success": success,
            "actor": detect_actor(),
            "argv0": effective_argv0,
        }

        if entry_name:
            record["entry"] = entry_name

        if details:
            record["details"] = details

        record["prev_hmac"] = prev_hmac
        record["hmac"] = _compute_hmac(hmac_key, record)

        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        _ensure_secure_permissions(log_path)
    except Exception:
        print(f"WARNING: audit log write failed ({log_path})", file=sys.stderr)


def verify_audit_log(log_path: Path | None = None) -> dict:
    """Verify the cryptographic HMAC-SHA256 hash chain of the audit log."""
    target = log_path or get_log_path()
    if not target.exists():
        return {"valid": True, "checked": 0, "error": None, "failed_line": None}

    try:
        hmac_key = _get_or_create_hmac_key()
        raw_lines = target.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        return {"valid": False, "checked": 0, "error": f"Unable to read log: {e}", "failed_line": None}

    expected_prev = GENESIS_HMAC
    checked = 0

    for line_num, raw in enumerate(raw_lines, 1):
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            return {
                "valid": False,
                "checked": checked,
                "error": f"Line {line_num}: invalid JSON",
                "failed_line": line_num,
            }

        if not isinstance(record, dict):
            return {
                "valid": False,
                "checked": checked,
                "error": f"Line {line_num}: record is not a JSON object",
                "failed_line": line_num,
            }

        prev_hmac = record.get("prev_hmac")
        actual_hmac = record.get("hmac")
        if not isinstance(prev_hmac, str) or not isinstance(actual_hmac, str):
            return {
                "valid": False,
                "checked": checked,
                "error": f"Line {line_num}: missing prev_hmac or hmac signature",
                "failed_line": line_num,
            }

        if not hmac.compare_digest(prev_hmac, expected_prev):
            return {
                "valid": False,
                "checked": checked,
                "error": f"Line {line_num}: broken hash chain (prev_hmac mismatch)",
                "failed_line": line_num,
            }

        computed = _compute_hmac(hmac_key, record)
        if not hmac.compare_digest(actual_hmac, computed):
            return {
                "valid": False,
                "checked": checked,
                "error": f"Line {line_num}: HMAC signature mismatch (record tampered)",
                "failed_line": line_num,
            }

        expected_prev = actual_hmac
        checked += 1

    return {"valid": True, "checked": checked, "error": None, "failed_line": None}


def get_recent_logs(limit: int = 50) -> list[dict]:
    """Get recent audit log entries, most recent first."""
    log_path = get_log_path()

    if not log_path.exists():
        return []

    try:
        with open(log_path, encoding="utf-8") as f:
            lines = f.readlines()

        entries = []
        for line in reversed(lines[-limit:]):
            try:
                entries.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue

        return entries
    except Exception:
        return []


def get_sanitized_recent_logs(limit: int = 20) -> list[dict]:
    """Return recent audit records stripped of HMAC material and unsafe detail values."""
    safe_limit = max(1, min(int(limit), 100))
    raw_logs = get_recent_logs(limit=safe_limit)
    sanitized: list[dict] = []
    for rec in raw_logs:
        item: dict[str, object] = {
            "timestamp": rec.get("timestamp"),
            "operation": rec.get("operation"),
            "success": bool(rec.get("success", True)),
        }
        if "entry" in rec:
            item["entry"] = rec["entry"]
        if isinstance(rec.get("actor"), dict):
            actor = rec["actor"]
            item["actor"] = {
                "type": actor.get("type"),
                "client": actor.get("client"),
                "pid": actor.get("pid"),
            }
        if "argv0" in rec:
            item["argv0"] = rec["argv0"]
        if isinstance(rec.get("details"), dict):
            clean_details = {
                k: v for k, v in rec["details"].items() if k in _SAFE_DETAIL_KEYS
            }
            if clean_details:
                item["details"] = clean_details
        sanitized.append(item)
    return sanitized


def clear_logs() -> bool:
    """Clear the audit log."""
    log_path = get_log_path()

    try:
        if log_path.exists():
            log_path.unlink()
        return True
    except Exception:
        return False
