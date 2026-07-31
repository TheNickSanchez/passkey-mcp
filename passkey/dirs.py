"""Cross-platform directory resolution for passkey data and config."""

import os
import sys
from pathlib import Path


def get_data_dir() -> Path:
    """Return the platform-appropriate data directory for passkey.

    The PASSKEY_DATA_DIR environment variable overrides platform detection
    (used by the test suite and portable setups).

    - macOS:   ~/Library/Application Support/passkey/
    - Linux:   $XDG_CONFIG_HOME/passkey  or  ~/.config/passkey/
    - Windows: %APPDATA%/passkey/
    """
    override = os.environ.get("PASSKEY_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return base / "passkey"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "passkey"
    # Linux / other POSIX
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "passkey"


def get_legacy_data_dir() -> Path:
    """Return the old ~/.passkey path used before cross-platform support."""
    return Path.home() / ".passkey"


def ensure_data_dir() -> Path:
    """Create and return the data directory with secure permissions."""
    data_dir = get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return data_dir


def check_migration_needed() -> bool:
    """Return True if a legacy ~/.passkey directory exists and new dir is empty."""
    legacy = get_legacy_data_dir()
    new = get_data_dir()
    if not legacy.exists():
        return False
    return not (new.exists() and any(new.iterdir()))


def run_migration_if_needed() -> None:
    """If legacy data dir exists and new one is empty, migrate files over."""
    if not check_migration_needed():
        return

    legacy = get_legacy_data_dir()
    new = get_data_dir()
    new.mkdir(parents=True, exist_ok=True, mode=0o700)

    migrated = []
    for item in legacy.iterdir():
        if item.is_file():
            dest = new / item.name
            if not dest.exists():
                import shutil

                shutil.copy2(item, dest)
                dest.chmod(0o600)
                migrated.append(item.name)

    if migrated:
        import sys

        print(
            f"[passkey] Migrated {len(migrated)} file(s) from {legacy} to {new}",
            file=sys.stderr,
        )
