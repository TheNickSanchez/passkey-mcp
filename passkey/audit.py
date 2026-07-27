"""Audit logging for passkey operations."""

import json
import os
from datetime import datetime
from pathlib import Path

from .dirs import get_data_dir


def get_log_path() -> Path:
    """Get the audit log path, creating directory if needed."""
    default = get_data_dir() / "audit.log"
    log_path = Path(os.environ.get("PASSKEY_AUDIT_LOG", default))
    log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return log_path


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
) -> None:
    """Log an operation to the audit log.

    Args:
        operation: The operation type (create, read, update, delete, import, export)
        entry_name: The entry involved, if any
        details: Additional details as dict
        success: Whether the operation succeeded
    """
    log_path = get_log_path()

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
        # Silently fail - don't break operations due to logging
        pass


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
