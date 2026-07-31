"""Keychain CRUD operations for passkey entries.

Secrets live in the OS keychain (one keychain item per entry). The entry
*index* — the list of entry names — lives in a plain file
(``entries.json`` in the data dir) with atomic writes, guarded by a
PID-aware lock file. Older versions stored the index in the keychain as
the ``__entries__`` item; it is migrated to the file on first read.
"""

import contextlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

from .audit import log_operation
from .dirs import ensure_data_dir, get_data_dir
from .models import Entry

SERVICE = "passkey"
METADATA_KEY = "__entries__"  # legacy keychain-held index (migrated to file)

# --- Concurrency Lock ---
LOCK_TIMEOUT = 10  # seconds


def _get_lock_file() -> Path:
    return get_data_dir() / "metadata.lock"


def _get_index_path() -> Path:
    return get_data_dir() / "entries.json"


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
    """Base exception for passkey errors."""

    pass


class KeychainAccessError(PasskeyError):
    """Raised when Keychain access fails."""

    pass


class EntryCorruptedError(PasskeyError):
    """Raised when entry data cannot be parsed."""

    pass


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


# --- Entry index (file-based, atomic writes) ---


def _write_index_nolock(names: list[str]) -> None:
    """Atomically write the entry index (temp file + os.replace, 0o600)."""
    path = _get_index_path()
    ensure_data_dir()
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".entries-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(names))
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _migrate_legacy_index() -> list[str]:
    """One-time migration: move the keychain-held ``__entries__`` index to a file."""
    try:
        legacy = keyring.get_password(SERVICE, METADATA_KEY)
    except KeyringError as e:
        raise KeychainAccessError(_keyring_error_message(e)) from e
    if not legacy:
        return []
    try:
        names = json.loads(legacy)
    except json.JSONDecodeError as e:
        raise EntryCorruptedError(
            f"Entry metadata is corrupted. Consider deleting '{METADATA_KEY}' "
            f"from Keychain Access app and re-creating entries. Error: {e}"
        ) from e
    _write_index_nolock(names)
    with contextlib.suppress(Exception):
        keyring.delete_password(SERVICE, METADATA_KEY)
    log_operation("metadata_migration", details={"count": len(names), "format": "file-index"})
    return names


def _read_index_nolock() -> list[str]:
    """Read the entry index file (migrating the legacy keychain index if needed)."""
    path = _get_index_path()
    if not path.exists():
        return _migrate_legacy_index()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise EntryCorruptedError(
            f"Entry index is corrupted. Fix or delete '{path}'. Error: {e}"
        ) from e
    if not isinstance(data, list):
        raise EntryCorruptedError(f"Entry index is corrupted (not a list): '{path}'")
    return data


def list_entries() -> list[str]:
    """Get list of all stored entry names.

    This function is thread-safe and acquires a lock.

    Returns:
        List of entry names, empty list if none exist.

    Raises:
        KeychainAccessError: If Keychain access fails.
        EntryCorruptedError: If the entry index is corrupted.
    """
    with _metadata_lock():
        return _read_index_nolock()


def save_entry(entry: Entry, is_update: bool = False) -> None:
    """Save entry to Keychain.

    Stores the entry's fields as JSON and updates the file index
    to track the entry name.

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

        # Now, atomically update the index
        with _metadata_lock():
            current_entries = _read_index_nolock()
            is_new = entry.name not in current_entries
            if is_new:
                current_entries.append(entry.name)
                current_entries.sort()
                _write_index_nolock(current_entries)

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


def _get_entry(name: str, *, log_read: bool) -> Entry | None:
    """Retrieve entry from Keychain by name (internal; read logging optional)."""
    try:
        # This operation is atomic and does not need the metadata lock
        data = keyring.get_password(SERVICE, name)
        if not data:
            # Before returning None, ensure it's not a dangling entry in the index
            with _metadata_lock():
                entries = _read_index_nolock()
                if name in entries:
                    entries.remove(name)
                    _write_index_nolock(entries)
                    log_operation(
                        "metadata_cleanup", name, details={"reason": "dangling entry found"}
                    )
            return None

        entry = Entry.from_json(name, data)
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


def delete_entry(name: str) -> bool:
    """Delete entry from Keychain.

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

    # Update the index atomically
    try:
        with _metadata_lock():
            entries = _read_index_nolock()
            if name in entries:
                entries.remove(name)
                _write_index_nolock(entries)
                # If we thought it was deleted, but it wasn't in the index, it wasn't really
                deleted = True
            elif deleted:
                # We deleted a password but it wasn't in our index.
                # This implies a dangling password. Log it.
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


def get_all_entries() -> list[Entry]:
    """Get all entries with full data.

    Reads every entry without logging a per-entry "read" (that made
    ``passkey list`` spam the audit log); a single bulk read is logged.

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

    if entries:
        log_operation("read", details={"bulk": True, "count": len(entries)})

    return entries
