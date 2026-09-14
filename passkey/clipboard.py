"""Clipboard utilities for passkey."""

import hashlib
import subprocess
import sys
import threading

import pyperclip

# Track the current secret for cleanup
_clipboard_secret = None
_clear_timer = None


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


def _clear_if_matches(secret_text: str | None = None) -> None:
    """Clear clipboard if it still contains our secret."""
    global _clipboard_secret
    expected = secret_text if secret_text is not None else _clipboard_secret
    if expected is None:
        return
    try:
        current = pyperclip.paste()
        if current == expected:
            pyperclip.copy("")
    except Exception:
        pass
    finally:
        if secret_text is None or secret_text == _clipboard_secret:
            _clipboard_secret = None


def _spawn_detached_clear(text: str, timeout_seconds: int) -> None:
    """Spawn a detached background process to clear clipboard after timeout.

    This ensures the clipboard is cleared even after the parent CLI process exits.
    We match against the SHA-256 hash of the secret rather than placing the raw
    secret in process arguments.
    """
    secret_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    worker_script = (
        "import time, hashlib, sys\n"
        "try:\n"
        "    import pyperclip\n"
        f"    time.sleep({timeout_seconds})\n"
        "    val = pyperclip.paste()\n"
        f"    if hashlib.sha256(val.encode('utf-8')).hexdigest() == '{secret_hash}':\n"
        "        pyperclip.copy('')\n"
        "except Exception:\n"
        "    pass\n"
    )
    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    else:
        # DETACHED_PROCESS = 0x00000008, CREATE_NEW_PROCESS_GROUP = 0x00000200
        kwargs["creationflags"] = 0x00000008 | 0x00000200

    try:
        subprocess.Popen([sys.executable, "-c", worker_script], **kwargs)
    except Exception:
        pass


def copy_with_autoclear(text: str, timeout_seconds: int = 30) -> None:
    """Copy text to clipboard and auto-clear after timeout.

    Only clears if clipboard still contains the copied text,
    to avoid clearing user's own clipboard operations.

    Spawns a detached background helper so cleanup survives CLI exit.
    Also retains an in-process daemon timer for interactive loops.

    Args:
        text: The text to copy
        timeout_seconds: Seconds before auto-clear (default 30)
    """
    global _clipboard_secret, _clear_timer

    # Cancel any pending in-process timer
    if _clear_timer is not None:
        _clear_timer.cancel()

    _clipboard_secret = text
    pyperclip.copy(text)

    # 1. In-process timer for long-running interactive sessions
    _clear_timer = threading.Timer(timeout_seconds, _clear_if_matches)
    _clear_timer.daemon = True
    _clear_timer.start()

    # 2. Detached process worker to ensure clearing survives parent CLI exit
    _spawn_detached_clear(text, timeout_seconds)
