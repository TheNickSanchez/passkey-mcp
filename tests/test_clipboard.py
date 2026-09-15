"""Tests for clipboard copy-and-autoclear."""

from unittest.mock import MagicMock, patch

from passkey import clipboard


class TestCopyWithAutoclear:
    def test_copies_text(self):
        with (
            patch.object(clipboard.pyperclip, "copy") as mock_copy,
            patch("passkey.clipboard.subprocess.Popen") as mock_popen,
        ):
            mock_popen.return_value.stdin = MagicMock()
            clipboard.copy_with_autoclear("TOKEN:secret", timeout_seconds=30)

        mock_copy.assert_called_once_with("TOKEN:secret")

    def test_spawns_detached_helper_without_secret_in_argv(self):
        with (
            patch.object(clipboard.pyperclip, "copy"),
            patch("passkey.clipboard.subprocess.Popen") as mock_popen,
        ):
            proc = MagicMock()
            mock_popen.return_value = proc
            clipboard.copy_with_autoclear("super-secret", timeout_seconds=30)

        mock_popen.assert_called_once()
        args, kwargs = mock_popen.call_args
        argv = args[0]
        assert "super-secret" not in argv
        assert argv[-1] == "30"
        assert kwargs["start_new_session"] is True
        assert kwargs["close_fds"] is True
        proc.stdin.write.assert_called_once_with(b"super-secret")
        proc.stdin.close.assert_called_once()

    def test_does_not_register_atexit_clear(self):
        """Regression: atexit used to wipe the clipboard when get --all exited."""
        with (
            patch.object(clipboard.pyperclip, "copy"),
            patch("passkey.clipboard.subprocess.Popen") as mock_popen,
            patch("atexit.register") as mock_atexit,
        ):
            mock_popen.return_value.stdin = MagicMock()
            clipboard.copy_with_autoclear("secret", timeout_seconds=30)

        mock_atexit.assert_not_called()


class TestDelayedClear:
    def test_clears_when_clipboard_still_matches(self):
        state = {"clip": "secret"}
        with (
            patch("passkey.clipboard.time.sleep") as mock_sleep,
            patch.object(clipboard.pyperclip, "paste", lambda: state["clip"]),
            patch.object(clipboard.pyperclip, "copy", lambda t: state.update(clip=t)),
        ):
            clipboard._delayed_clear(30, "secret")

        mock_sleep.assert_called_once_with(30)
        assert state["clip"] == ""

    def test_leaves_clipboard_if_user_copied_something_else(self):
        state = {"clip": "user stuff"}
        with (
            patch("passkey.clipboard.time.sleep"),
            patch.object(clipboard.pyperclip, "paste", lambda: state["clip"]),
            patch.object(clipboard.pyperclip, "copy") as mock_copy,
        ):
            clipboard._delayed_clear(30, "secret")

        mock_copy.assert_not_called()
        assert state["clip"] == "user stuff"
