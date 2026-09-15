"""Clipboard utilities for passkey."""

import subprocess
import sys
import time
from pathlib import Path

import pyperclip


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


def _delayed_clear(timeout_seconds: int, secret: str) -> None:
    """Sleep, then clear the clipboard if it still holds *secret*."""
    time.sleep(timeout_seconds)
    try:
        if pyperclip.paste() == secret:
            pyperclip.copy("")
    except Exception:
        pass


def copy_with_autoclear(text: str, timeout_seconds: int = 30) -> None:
    """Copy text to clipboard and auto-clear after timeout.

    Spawns a detached helper so the clipboard survives CLI exit
    (``get --all``, ``generate``). The helper only clears if the
    clipboard still matches. The secret is passed on stdin, never argv.
    """
    pyperclip.copy(text)
    try:
        proc = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), str(int(timeout_seconds))],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        assert proc.stdin is not None
        proc.stdin.write(text.encode("utf-8"))
        proc.stdin.close()
    except Exception:
        # Copy already succeeded; auto-clear is best-effort.
        pass


if __name__ == "__main__":
    _delayed_clear(int(sys.argv[1]), sys.stdin.buffer.read().decode("utf-8"))
