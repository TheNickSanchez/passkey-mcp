"""Tests for passkey.dirs cross-platform directory logic."""

import os
import sys
from pathlib import Path
from unittest.mock import patch


class TestGetDataDir:
    """Tests for get_data_dir()."""

    def test_posix_uses_xdg_config(self, monkeypatch):
        """On POSIX, returns $XDG_CONFIG_HOME/passkey when set."""
        monkeypatch.setenv("XDG_CONFIG_HOME", "/custom/config")
        monkeypatch.setattr(sys, "platform", "linux")
        # Re-import after patching
        import importlib

        import passkey.dirs as dirs
        importlib.reload(dirs)
        result = dirs.get_data_dir()
        assert result == Path("/custom/config/passkey")

    def test_posix_defaults_to_home_config(self, monkeypatch):
        """On POSIX without XDG set, returns ~/.config/passkey."""
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(sys, "platform", "linux")
        import importlib

        import passkey.dirs as dirs
        importlib.reload(dirs)
        result = dirs.get_data_dir()
        assert result == Path.home() / ".config" / "passkey"

    def test_windows_uses_appdata(self, monkeypatch, tmp_path):
        """On Windows, returns %APPDATA%/passkey."""
        monkeypatch.setenv("APPDATA", str(tmp_path))
        monkeypatch.setattr(sys, "platform", "win32")
        import importlib

        import passkey.dirs as dirs
        importlib.reload(dirs)
        result = dirs.get_data_dir()
        assert result == tmp_path / "passkey"

    def test_macos_returns_library_app_support(self, monkeypatch):
        """On macOS (darwin), returns ~/Library/Application Support/passkey."""
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.setattr(sys, "platform", "darwin")
        import importlib

        import passkey.dirs as dirs
        importlib.reload(dirs)
        result = dirs.get_data_dir()
        assert result == Path.home() / "Library" / "Application Support" / "passkey"


class TestGetLegacyDataDir:
    """Tests for get_legacy_data_dir()."""

    def test_returns_home_passkey(self):
        """Returns ~/.passkey regardless of platform."""
        from passkey.dirs import get_legacy_data_dir
        result = get_legacy_data_dir()
        assert result == Path.home() / ".passkey"


class TestEnsureDataDir:
    """Tests for ensure_data_dir()."""

    def test_creates_directory(self, tmp_path, monkeypatch):
        """Creates the data directory if it doesn't exist."""
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        import passkey.dirs as dirs
        # Override get_data_dir to use tmp_path
        target = tmp_path / "passkey"
        with patch.object(dirs, "get_data_dir", return_value=target):
            result = dirs.ensure_data_dir()
        assert result.exists()
        assert result.is_dir()


class TestMigration:
    """Tests for migration logic."""

    def test_migration_not_needed_when_no_legacy(self, tmp_path, monkeypatch):
        """No migration when legacy dir doesn't exist."""
        import passkey.dirs as dirs
        fake_legacy = tmp_path / "old"
        fake_new = tmp_path / "new"
        with patch.object(dirs, "get_legacy_data_dir", return_value=fake_legacy), \
             patch.object(dirs, "get_data_dir", return_value=fake_new):
            assert dirs.check_migration_needed() is False

    def test_migration_not_needed_when_new_has_files(self, tmp_path, monkeypatch):
        """No migration when new dir already has content."""
        import passkey.dirs as dirs
        fake_legacy = tmp_path / "old"
        fake_new = tmp_path / "new"
        fake_legacy.mkdir()
        fake_new.mkdir()
        (fake_new / "audit.log").write_text("data")
        with patch.object(dirs, "get_legacy_data_dir", return_value=fake_legacy), \
             patch.object(dirs, "get_data_dir", return_value=fake_new):
            assert dirs.check_migration_needed() is False

    def test_migration_needed_when_legacy_exists_new_empty(self, tmp_path):
        """Migration needed when legacy exists and new is empty."""
        import passkey.dirs as dirs
        fake_legacy = tmp_path / "old"
        fake_new = tmp_path / "new"
        fake_legacy.mkdir()
        (fake_legacy / "audit.log").write_text("data")
        with patch.object(dirs, "get_legacy_data_dir", return_value=fake_legacy), \
             patch.object(dirs, "get_data_dir", return_value=fake_new):
            assert dirs.check_migration_needed() is True

    def test_run_migration_copies_files(self, tmp_path):
        """run_migration_if_needed copies files from legacy to new dir."""
        import passkey.dirs as dirs
        fake_legacy = tmp_path / "old"
        fake_new = tmp_path / "new"
        fake_legacy.mkdir()
        test_file = fake_legacy / "audit.log"
        test_file.write_text("log data")

        with patch.object(dirs, "get_legacy_data_dir", return_value=fake_legacy), \
             patch.object(dirs, "get_data_dir", return_value=fake_new):
            dirs.run_migration_if_needed()

        assert (fake_new / "audit.log").exists()
        assert (fake_new / "audit.log").read_text() == "log data"


class TestProcessLocking:
    """Tests for cross-platform process lock checking."""

    def test_stale_lock_detected_for_dead_pid(self, tmp_path, monkeypatch):
        """Lock file with non-existent PID is detected as stale."""
        import passkey.keychain as kc
        lock_file = tmp_path / "metadata.lock"
        lock_file.write_text("9999999")  # Very unlikely real PID

        with patch.object(kc, "_get_lock_file", return_value=lock_file):
            # Force the process to be "not alive"
            with patch.object(kc, "_is_process_alive", return_value=False):
                assert kc._is_lock_stale() is True

    def test_fresh_lock_not_stale(self, tmp_path):
        """Lock file with current PID is not stale."""
        import passkey.keychain as kc
        lock_file = tmp_path / "metadata.lock"
        lock_file.write_text(str(os.getpid()))

        with patch.object(kc, "_get_lock_file", return_value=lock_file):
            with patch.object(kc, "_is_process_alive", return_value=True):
                assert kc._is_lock_stale() is False
