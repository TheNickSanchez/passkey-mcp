"""Tests for passkey.settings module and the require_auth CLI gate."""

import json

import pytest

from passkey.keychain import PasskeyError
from passkey.settings import (
    cmd_config,
    get_default_policy,
    get_setting,
    has_explicit_default_policy,
    load_settings,
    require_auth_enabled,
    set_setting,
)


class TestLoadSettings:
    def test_defaults_when_no_file(self, isolated_data_dir):
        assert load_settings() == {
            "require_auth": False,
            "mcp_write_tools": True,
            "mcp_browser_broker": False,
            "agent_session_lease_ttl": 600,
            "default_policy": "allow",
        }

    def test_platform_default_policy_macos_lacontext_vs_headless(self, isolated_data_dir):
        from unittest.mock import patch

        with patch("passkey.settings.is_lacontext_available", return_value=True):
            assert load_settings()["default_policy"] == "session"
            assert get_default_policy() == "session"
            assert has_explicit_default_policy() is False

        with patch("passkey.settings.is_lacontext_available", return_value=False):
            assert load_settings()["default_policy"] == "allow"
            assert get_default_policy() == "allow"
            assert has_explicit_default_policy() is False

    def test_roundtrip(self, isolated_data_dir):
        set_setting("require_auth", True)
        assert load_settings()["require_auth"] is True
        # Unrelated settings must not lock in default_policy before FTUE onboarding
        assert has_explicit_default_policy() is False

    def test_corrupt_file_returns_defaults(self, isolated_data_dir):
        path = isolated_data_dir / "settings.json"
        isolated_data_dir.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json")
        assert load_settings() == {
            "require_auth": False,
            "mcp_write_tools": True,
            "mcp_browser_broker": False,
            "agent_session_lease_ttl": 600,
            "default_policy": "allow",
        }

    def test_wrong_type_falls_back_to_default(self, isolated_data_dir):
        isolated_data_dir.mkdir(parents=True, exist_ok=True)
        (isolated_data_dir / "settings.json").write_text(
            json.dumps({"require_auth": "yes please", "default_policy": "yolo"})
        )
        assert load_settings()["require_auth"] is False
        assert load_settings()["default_policy"] == "allow"
        assert has_explicit_default_policy() is False


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

    def test_default_policy_cli_roundtrip_and_validation(self, isolated_data_dir, capsys):
        assert has_explicit_default_policy() is False
        cmd_config("default-policy", "session", json_output=True)
        out = json.loads(capsys.readouterr().out)
        assert out == {"key": "default_policy", "value": "session", "updated": True}
        assert get_default_policy() == "session"
        assert has_explicit_default_policy() is True

        # Persists even after changing another setting
        set_setting("require_auth", True)
        assert has_explicit_default_policy() is True
        assert get_default_policy() == "session"

        cmd_config("default-policy", "prompt")
        assert "Set default-policy = prompt" in capsys.readouterr().out
        assert get_default_policy() == "prompt"

        with pytest.raises(PasskeyError, match="Invalid policy"):
            cmd_config("default-policy", "yolo")


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
