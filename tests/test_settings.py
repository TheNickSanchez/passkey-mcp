"""Tests for passkey.settings module and the require_auth CLI gate."""

import json

import pytest

from passkey.keychain import PasskeyError
from passkey.settings import (
    cmd_config,
    get_setting,
    load_settings,
    require_auth_enabled,
    set_setting,
)


class TestLoadSettings:
    def test_defaults_when_no_file(self, isolated_data_dir):
        assert load_settings() == {"require_auth": False}

    def test_roundtrip(self, isolated_data_dir):
        set_setting("require_auth", True)
        assert load_settings()["require_auth"] is True

    def test_corrupt_file_returns_defaults(self, isolated_data_dir):
        path = isolated_data_dir / "settings.json"
        isolated_data_dir.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json")
        assert load_settings() == {"require_auth": False}

    def test_wrong_type_falls_back_to_default(self, isolated_data_dir):
        isolated_data_dir.mkdir(parents=True, exist_ok=True)
        (isolated_data_dir / "settings.json").write_text(
            json.dumps({"require_auth": "yes please"})
        )
        assert load_settings()["require_auth"] is False


class TestSetSetting:
    def test_file_permissions(self, isolated_data_dir):
        set_setting("require_auth", True)
        path = isolated_data_dir / "settings.json"
        assert oct(path.stat().st_mode & 0o777) == "0o600"

    def test_unknown_key_rejected(self):
        with pytest.raises(PasskeyError, match="Unknown setting"):
            set_setting("nonsense", True)

    def test_wrong_type_rejected(self):
        with pytest.raises(PasskeyError, match="must be of type"):
            set_setting("require_auth", "on")  # must be real bool, not str

    def test_dash_style_key_normalized(self, isolated_data_dir):
        set_setting("require-auth", True)
        assert require_auth_enabled() is True


class TestGetSetting:
    def test_get_known(self):
        assert get_setting("require_auth") is False

    def test_get_unknown(self):
        with pytest.raises(PasskeyError, match="Unknown setting"):
            get_setting("bogus")


class TestCmdConfig:
    def test_show_all(self, capsys):
        cmd_config()
        out = capsys.readouterr().out
        assert "require-auth = False" in out

    def test_show_one(self, capsys):
        cmd_config("require-auth")
        assert "require-auth = False" in capsys.readouterr().out

    def test_set_on_off(self, capsys):
        cmd_config("require-auth", "on")
        assert require_auth_enabled() is True
        cmd_config("require-auth", "off")
        assert require_auth_enabled() is False

    def test_set_invalid_value(self):
        with pytest.raises(PasskeyError, match="Expected on/off"):
            cmd_config("require-auth", "maybe")


class TestRequireAuthGate:
    """The CLI gate: no-op by default, delegates to auth when opted in."""

    def test_gate_off_by_default(self, no_os_auth):
        from unittest.mock import patch

        no_os_auth.stop()  # exercise the real gate
        from passkey.cli import _require_auth

        with patch("passkey.auth.require_auth") as mock_auth:
            _require_auth("test")
        mock_auth.assert_not_called()

    def test_gate_on_when_enabled(self, no_os_auth):
        from unittest.mock import patch

        no_os_auth.stop()  # exercise the real gate
        set_setting("require_auth", True)
        from passkey.cli import _require_auth

        with patch("passkey.auth.require_auth") as mock_auth:
            _require_auth("test operation")
        mock_auth.assert_called_once_with("test operation")

    def test_run_is_never_gated(self, no_os_auth):
        """passkey run must work headless even with require_auth on."""
        import sys as _sys
        from unittest.mock import patch

        no_os_auth.stop()  # exercise the real dispatch
        set_setting("require_auth", True)

        from passkey.cli import main

        with patch.object(_sys, "argv", ["passkey", "run", "slack", "--", "echo", "hi"]), \
             patch("passkey.cli.handle_run_command") as mock_run, \
             patch("passkey.auth.require_auth") as mock_auth, \
             patch("passkey.dirs.run_migration_if_needed"):
            main()
        mock_run.assert_called_once()
        mock_auth.assert_not_called()
