"""OS-level authentication for sensitive passkey operations.

This module is only reached when the user has explicitly opted in via
``passkey config require-auth on``. The primary protection for secrets is
always the OS keychain's own ACL; this is an optional extra prompt for
interactive terminal sessions. Headless code paths (``passkey run`` from
an MCP server) never call into this module.

Platform notes:

- macOS: ``sudo -v`` via the system PAM stack (Touch ID if pam_tid is
  configured). Requires a tty; without one it simply fails closed.
- Linux: ``pkexec`` polkit dialog, with a getpass+sudo fallback.
- Windows: deliberately a no-op. The previous implementation used
  ShellExecuteW "runas", which elevates a *separate* process and proves
  nothing about the current one — security theater, dropped. Windows
  protection comes from Credential Manager ACLs alone.
"""

import subprocess
import sys

from .keychain import PasskeyError


def _authenticate_macOS() -> bool:
    """Trigger macOS authentication dialog (Touch ID / password).

    Uses 'sudo -v' which validates credentials via the system PAM stack.
    This honors the user's PAM configuration, including Touch ID (pam_tid.so)
    if set up in /etc/pam.d/sudo.

    If credentials are cached by sudo, no dialog is shown (same 5-min window).
    """
    try:
        result = subprocess.run(
            ["sudo", "-v"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        return False


def _authenticate_linux() -> bool:
    """Trigger Linux polkit authentication dialog.

    Uses pkexec which shows a native desktop authentication dialog
    (GNOME, KDE, etc.) via PolicyKit.
    """
    try:
        result = subprocess.run(
            ["/usr/bin/pkexec", "/usr/bin/true"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0
    except FileNotFoundError:
        # pkexec not available, fall back to sudo
        return _authenticate_sudo_fallback()
    except subprocess.TimeoutExpired:
        return False


def _authenticate_windows() -> bool:
    """Honest no-op on Windows.

    There is no meaningful per-process auth oracle available to us on
    Windows (UAC elevates a separate process, which proves nothing about
    this one). Rather than pretend, we rely on Windows Credential Manager
    ACLs and tell the user so.
    """
    print(
        "Note: OS-auth prompts are not supported on Windows; "
        "relying on Credential Manager access controls.",
        file=sys.stderr,
    )
    return True


def _authenticate_sudo_fallback() -> bool:
    """Fallback: use getpass + sudo -S to verify user password.

    This is less elegant (no GUI dialog) but works everywhere.
    """
    import getpass

    try:
        password = getpass.getpass("Admin password required: ")
        result = subprocess.run(
            ["sudo", "-S", "true"],
            input=password + "\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        return False


def authenticate(reason: str = "Authenticate to access secrets") -> bool:
    """Trigger OS-level authentication.

    Displays the native system authentication dialog (Touch ID, admin
    password, UAC, or polkit). The specific mechanism depends on the OS.

    Args:
        reason: Not used on all platforms, but provided for consistency

    Returns:
        True if authentication succeeded, False otherwise
    """
    if sys.platform == "darwin":
        return _authenticate_macOS()
    elif sys.platform == "linux":
        return _authenticate_linux()
    elif sys.platform == "win32":
        return _authenticate_windows()
    else:
        return _authenticate_sudo_fallback()


def require_auth(operation: str = "access secrets") -> None:
    """Require authentication or raise PasskeyError.

    Args:
        operation: Description of what requires auth (for error message)

    Raises:
        PasskeyError: If authentication fails or is cancelled
    """
    if not authenticate():
        raise PasskeyError(
            f"Authentication required to {operation}. Authentication failed or was cancelled."
        )
