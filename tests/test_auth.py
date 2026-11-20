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


class TestIsLAContextAvailable:
    def test_false_when_disabled_or_non_darwin(self, monkeypatch):
        from passkey.auth import is_lacontext_available

        # Disabled via PASSKEY_DISABLE_LACONTEXT=1 (default in conftest)
        assert is_lacontext_available() is False

        monkeypatch.setenv("PASSKEY_DISABLE_LACONTEXT", "0")
        monkeypatch.setattr(sys, "platform", "linux")
        assert is_lacontext_available() is False

        monkeypatch.setattr(sys, "platform", "darwin")
        with patch("passkey.auth.ctypes.CDLL", side_effect=OSError("missing framework")):
            assert is_lacontext_available() is False

    @pytest.mark.parametrize(
        "can_eval_result,expected",
        [
            (True, True),
            (False, False),
            (RuntimeError("coreauthd failure"), False),
        ],
    )
    def test_mocked_cdll_can_evaluate_policy_and_finally_release(
        self, monkeypatch, can_eval_result, expected
    ):
        import ctypes as _ctypes

        from passkey.auth import _LA_POLICY_DEVICE_OWNER_AUTH, is_lacontext_available

        monkeypatch.setenv("PASSKEY_DISABLE_LACONTEXT", "0")
        monkeypatch.setattr(sys, "platform", "darwin")

        fake_objc = MagicMock()
        fake_objc.objc_getClass.return_value = 0x1000
        selectors = {
            b"alloc": 101,
            b"init": 102,
            b"release": 103,
            b"canEvaluatePolicy:error:": 104,
        }
        fake_objc.sel_registerName.side_effect = lambda name: selectors[name]

        eval_calls: list[tuple[int, int, int]] = []
        release_calls: list[tuple[int, int]] = []

        def _fake_cfunctype(restype, *argtypes):
            def _bind(_addr):
                if restype is _ctypes.c_void_p:
                    return lambda receiver, sel: 0x2000 if sel == 101 else 0x3000
                if restype is None:
                    return lambda receiver, sel: release_calls.append((receiver, sel))
                if restype is _ctypes.c_bool:
                    def _can_eval(ctx, sel, policy, _err_ptr):
                        eval_calls.append((ctx, sel, policy))
                        if isinstance(can_eval_result, Exception):
                            raise can_eval_result
                        return can_eval_result

                    return _can_eval
                raise AssertionError(f"Unexpected restype: {restype}")

            return _bind

        with (
            patch("passkey.auth.ctypes.CDLL", side_effect=[fake_objc, MagicMock()]),
            patch("passkey.auth.ctypes.cast", return_value=MagicMock(value=0xCAFEBABE)),
            patch("passkey.auth.ctypes.CFUNCTYPE", side_effect=_fake_cfunctype),
        ):
            assert is_lacontext_available() is expected

        assert eval_calls == [(0x3000, 104, _LA_POLICY_DEVICE_OWNER_AUTH)]
        # LAContext instance must always be released in finally, even on error
        assert release_calls == [(0x3000, 103)]
