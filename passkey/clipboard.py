"""Clipboard utilities for passkey."""

import atexit
import threading

import pyperclip

# Track the current secret for cleanup on exit
_clipboard_secret = None
_clear_timer = None
_cleanup_registered = False


def copy_to_clipboard(text: str) -> None:
    """Copy text to system clipboard.

    Args:
        text: The text to copy

    Raises:
        pyperclip.PyperclipException: If clipboard access fails
    """
    pyperclip.copy(text)


def clear_clipboard() -> None:
    """Clear the system clipboard."""
    pyperclip.copy("")


def _clear_if_matches():
    """Clear clipboard if it still contains our secret."""
    global _clipboard_secret
    if _clipboard_secret is None:
        return
    try:
        current = pyperclip.paste()
        if current == _clipboard_secret:
            pyperclip.copy("")
    except Exception:
        pass
    finally:
        _clipboard_secret = None


def copy_with_autoclear(text: str, timeout_seconds: int = 30) -> None:
    """Copy text to clipboard and auto-clear after timeout.

    Only clears if clipboard still contains the copied text,
    to avoid clearing user's own clipboard operations.

    Guarantees cleanup via:
    - Timer-based clear after timeout
    - atexit handler for process exit

    Args:
        text: The text to copy
        timeout_seconds: Seconds before auto-clear (default 30)
    """
    global _clipboard_secret, _clear_timer, _cleanup_registered

    # Cancel any pending clear from previous copy
    if _clear_timer is not None:
        _clear_timer.cancel()

    # Track the secret for exit cleanup
    _clipboard_secret = text
    pyperclip.copy(text)

    # Register atexit handler once
    if not _cleanup_registered:
        atexit.register(_clear_if_matches)
        _cleanup_registered = True

    # Timer-based cleanup (daemon so it doesn't block Ctrl+C/exit)
    # The atexit handler ensures cleanup on normal process exit
    _clear_timer = threading.Timer(timeout_seconds, _clear_if_matches)
    _clear_timer.daemon = True
    _clear_timer.start()
