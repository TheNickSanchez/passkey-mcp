"""Tests for passkey.auth module — all subprocess/OS calls fully mocked."""

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from passkey.auth import (
    _authenticate_linux,
    _authenticate_macOS,
    _authenticate_sudo_fallback,
    _authenticate_windows,
    authenticate,
    require_auth,
)
from passkey.keychain import PasskeyError


def _run_result(returncode=0):
    result = MagicMock()
    result.returncode = returncode
    return result


class TestAuthenticateMacOS:
    def test_success(self):
        with patch("passkey.auth.subprocess.run", return_value=_run_result(0)) as mock_run:
            assert _authenticate_macOS() is True
        mock_run.assert_called_once_with(
            ["sudo", "-v"], capture_output=True, text=True, timeout=120
        )

    def test_failure(self):
        with patch("passkey.auth.subprocess.run", return_value=_run_result(1)):
            assert _authenticate_macOS() is False

    def test_sudo_missing(self):
        with patch("passkey.auth.subprocess.run", side_effect=FileNotFoundError):
            assert _authenticate_macOS() is False

    def test_timeout(self):
        with patch(
            "passkey.auth.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="sudo", timeout=120),
        ):
            assert _authenticate_macOS() is False


class TestAuthenticateLinux:
    def test_pkexec_success(self):
        with patch("passkey.auth.subprocess.run", return_value=_run_result(0)) as mock_run:
            assert _authenticate_linux() is True
        mock_run.assert_called_once_with(
            ["/usr/bin/pkexec", "/usr/bin/true"], capture_output=True, text=True, timeout=120
        )

    def test_pkexec_failure(self):
        with patch("passkey.auth.subprocess.run", return_value=_run_result(1)):
            assert _authenticate_linux() is False

    def test_pkexec_timeout(self):
        with patch(
            "passkey.auth.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="pkexec", timeout=120),
        ):
            assert _authenticate_linux() is False

    def test_pkexec_missing_falls_back_to_sudo(self):
        with patch("passkey.auth.subprocess.run", side_effect=FileNotFoundError), \
             patch("passkey.auth._authenticate_sudo_fallback", return_value=True) as mock_fb:
            assert _authenticate_linux() is True
        mock_fb.assert_called_once()


class TestSudoFallback:
    def test_success(self):
        with patch("getpass.getpass", return_value="hunter2"), \
             patch("passkey.auth.subprocess.run", return_value=_run_result(0)) as mock_run:
            assert _authenticate_sudo_fallback() is True
        # Password goes via stdin, never argv
        assert mock_run.call_args.kwargs.get("input") == "hunter2\n"

    def test_wrong_password(self):
        with patch("getpass.getpass", return_value="nope"), \
             patch("passkey.auth.subprocess.run", return_value=_run_result(1)):
            assert _authenticate_sudo_fallback() is False

    def test_keyboard_interrupt(self):
        with patch("getpass.getpass", side_effect=KeyboardInterrupt):
            assert _authenticate_sudo_fallback() is False


class TestAuthenticateWindows:
    """Windows is an honest no-op: no UAC theater, relies on Credential Manager."""

    def test_returns_true_with_note(self, capsys):
        assert _authenticate_windows() is True
        captured = capsys.readouterr()
        assert "not supported on Windows" in captured.err

    def test_no_subprocess_or_ctypes_invoked(self):
        with patch("passkey.auth.subprocess.run") as mock_run:
            _authenticate_windows()
        mock_run.assert_not_called()


class TestAuthenticateDispatch:
    def test_dispatch_macos(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("passkey.auth._authenticate_macOS", return_value=True) as m:
            assert authenticate() is True
        m.assert_called_once()

    def test_dispatch_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        with patch("passkey.auth._authenticate_linux", return_value=False) as m:
            assert authenticate() is False
        m.assert_called_once()

    def test_dispatch_windows(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        # Real implementation: honest no-op returning True
        assert authenticate() is True

    def test_dispatch_other_uses_fallback(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "freebsd")
        with patch("passkey.auth._authenticate_sudo_fallback", return_value=True) as m:
            assert authenticate() is True
        m.assert_called_once()


class TestRequireAuth:
    def test_success_does_not_raise(self):
        with patch("passkey.auth.authenticate", return_value=True):
            require_auth("test operation")

    def test_failure_raises_passkey_error(self):
        with patch("passkey.auth.authenticate", return_value=False), \
             pytest.raises(PasskeyError, match="test operation"):
            require_auth("test operation")
