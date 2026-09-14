"""Audit logging for passkey operations."""

import contextlib
import json
import os
from datetime import datetime
from pathlib import Path

from .dirs import get_data_dir

# When the log exceeds this size, the oldest half of the lines is dropped.
MAX_LOG_BYTES = 1_000_000  # ~1 MB

_DISALLOWED_PREFIXES = (
    "/etc",
    "/private/etc",
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/var/run",
    "/private/var/run",
    "/private/var/root",
    "/dev",
)

_SENSITIVE_FILENAMES = frozenset({
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".zprofile",
    ".bash_history",
    ".zsh_history",
})


def _validate_log_path(path: Path) -> None:
    """Validate that audit log does not target critical system or sensitive files."""
    try:
        resolved = path.resolve()
    except Exception:
        resolved = path

    for p in (path, resolved):
        path_str = str(p)
        for prefix in _DISALLOWED_PREFIXES:
            if path_str == prefix or path_str.startswith(prefix + "/"):
                raise ValueError(f"Audit log path cannot be inside system directory '{prefix}'")

        home = Path.home().resolve()
        for sensitive_sub in (".ssh", ".gnupg", ".aws"):
            sens_dir = home / sensitive_sub
            if path_str == str(sens_dir) or path_str.startswith(str(sens_dir) + "/"):
                raise ValueError(f"Audit log path cannot be inside sensitive directory '{sensitive_sub}'")

    if resolved.name in _SENSITIVE_FILENAMES or path.name in _SENSITIVE_FILENAMES:
        raise ValueError(f"Audit log path cannot target shell startup file '{path.name}'")


def get_log_path() -> Path:
    """Get the audit log path, creating directory if needed."""
    default = get_data_dir() / "audit.log"
    override = os.environ.get("PASSKEY_AUDIT_LOG")
    if override:
        log_path = Path(override).expanduser()
        if log_path.is_symlink():
            raise ValueError("Audit log path cannot be a symbolic link")
        _validate_log_path(log_path)
    else:
        log_path = default
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return log_path


def _rotate_if_needed(log_path: Path) -> None:
    """Cap the log size by dropping the oldest half of the lines."""
    try:
        if not log_path.exists() or log_path.is_symlink() or log_path.stat().st_size <= MAX_LOG_BYTES:
            return
        lines = log_path.read_text().splitlines(keepends=True)
        if lines:
            try:
                sample = json.loads(lines[0])
                if not isinstance(sample, dict) or "operation" not in sample:
                    return
            except json.JSONDecodeError:
                return
        keep = lines[len(lines) // 2 :]
        log_path.write_text("".join(keep))
    except OSError:
        pass


def _ensure_secure_permissions(path: Path) -> None:
    """Ensure file has secure permissions (owner only)."""
    if path.exists() and not path.is_symlink():
        current_mode = path.stat().st_mode & 0o777
        if current_mode != 0o600:
            with contextlib.suppress(OSError):
                path.chmod(0o600)


def log_operation(
    operation: str,
    entry_name: str | None = None,
    details: dict | None = None,
    success: bool = True,
) -> None:
    """Log an operation to the audit log.

    Args:
        operation: The operation type (create, read, update, delete, import, export)
        entry_name: The entry involved, if any
        details: Additional details as dict
        success: Whether the operation succeeded
    """
    log_path = get_log_path()
    _rotate_if_needed(log_path)

    record = {
        "timestamp": datetime.now().isoformat(),
        "operation": operation,
        "success": success,
    }

    if entry_name:
        record["entry"] = entry_name

    if details:
        record["details"] = details

    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
        # Ensure secure permissions on log file
        _ensure_secure_permissions(log_path)
    except Exception:
        import sys as _sys
        print(f"WARNING: audit log write failed ({log_path})", file=_sys.stderr)


def get_recent_logs(limit: int = 50) -> list[dict]:
    """Get recent audit log entries.

    Args:
        limit: Maximum number of entries to return

    Returns:
        List of log entries, most recent first
    """
    log_path = get_log_path()

    if not log_path.exists():
        return []

    try:
        with open(log_path) as f:
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


def clear_logs() -> bool:
    """Clear the audit log.

    Returns:
        True if successful, False otherwise
    """
    log_path = get_log_path()

    try:
        if log_path.exists():
            log_path.unlink()
        return True
    except Exception:
        return False
