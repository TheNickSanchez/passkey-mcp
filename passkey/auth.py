"""OS-level authentication for sensitive passkey operations and 'prompt' policy entries.

Security & Architecture Notes:
- Primary at-rest protection is the OS keychain ACL. Note that because ``passkey``
  runs under Python via ``keyring``, macOS Keychain item ACLs bind to the
  underlying ``python3`` interpreter binary rather than a standalone code-signed
  Mach-O executable.
- To enforce deterministic out-of-band human approval for ``policy="prompt"``
  entries (and ``passkey lease grant`` / ``require-auth``), macOS authentication
  first invokes ``LocalAuthentication.framework`` (``LAContext``) directly via
  ``ctypes`` + ``libobjc.A.dylib``. This triggers native Touch ID, Apple Watch,
  or macOS device-password dialogs via ``coreauthd`` even from headless stdio
  MCP child processes that have no controlling TTY and without requiring ``sudo``.
- When ``LAContext`` is unavailable (e.g., headless SSH without a GUI session or
  when ``PASSKEY_DISABLE_LACONTEXT=1`` is set in CI), macOS falls back to
  ``sudo -v``.
- Linux uses ``pkexec`` (PolicyKit GUI dialog) with a ``getpass`` + ``sudo -S``
  fallback. Windows remains a documented no-op relying on Credential Manager ACLs.
"""

import ctypes
import os
import subprocess
import sys
import threading
import time

from .keychain import PasskeyError

# LAPolicyDeviceOwnerAuthentication allows Touch ID, Apple Watch, OR user password
_LA_POLICY_DEVICE_OWNER_AUTH = 2


def _lacontext_enabled() -> bool:
    """Return True unless LAContext has been explicitly disabled (e.g. in test suites)."""
    return os.environ.get("PASSKEY_DISABLE_LACONTEXT", "").strip() not in (
        "1",
        "true",
        "yes",
    )


def is_lacontext_available() -> bool:
    """Return True when macOS LocalAuthentication (Touch ID / Watch / passcode) can be evaluated.

    Non-interactive capability check: queries ``canEvaluatePolicy:error:`` only
    and never triggers a Touch ID or password prompt.
    """
    if sys.platform != "darwin" or not _lacontext_enabled():
        return False

    try:
        objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        ctypes.CDLL(
            "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication"
        )
    except OSError:
        return False

    try:
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.objc_getClass.argtypes = [ctypes.c_char_p]
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]

        msg_send_addr = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
        if not msg_send_addr:
            return False

        msg_id = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(
            msg_send_addr
        )
        msg_void = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)(msg_send_addr)
        msg_can_eval = ctypes.CFUNCTYPE(
            ctypes.c_bool,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_long,
            ctypes.POINTER(ctypes.c_void_p),
        )(msg_send_addr)

        la_cls = objc.objc_getClass(b"LAContext")
        if not la_cls:
            return False

        sel_alloc = objc.sel_registerName(b"alloc")
        sel_init = objc.sel_registerName(b"init")
        sel_release = objc.sel_registerName(b"release")
        sel_can_eval = objc.sel_registerName(b"canEvaluatePolicy:error:")

        ctx_raw = msg_id(la_cls, sel_alloc)
        ctx = msg_id(ctx_raw, sel_init) if ctx_raw else None
        if not ctx:
            return False

        try:
            err_ptr = ctypes.c_void_p(0)
            return bool(
                msg_can_eval(
                    ctx,
                    sel_can_eval,
                    _LA_POLICY_DEVICE_OWNER_AUTH,
                    ctypes.byref(err_ptr),
                )
            )
        finally:
            msg_void(ctx, sel_release)
    except Exception:
        return False


def _evaluate_lacontext(reason: str, timeout: float = 120.0) -> bool | None:
    """Invoke macOS LocalAuthentication.framework LAContext out-of-band via ctypes.

    Returns:
        True if user approved via Touch ID / Apple Watch / password,
        False if user denied/cancelled or timed out,
        None if LocalAuthentication cannot be loaded or evaluated in this session
        (allowing caller to fall back to sudo -v).
    """
    if sys.platform != "darwin":
        return None

    try:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        ctypes.CDLL(
            "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication"
        )
    except OSError:
        return None

    try:
        objc.objc_getClass.restype = ctypes.c_void_p
        objc.objc_getClass.argtypes = [ctypes.c_char_p]
        objc.sel_registerName.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]

        msg_send_addr = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
        if not msg_send_addr:
            return None

        msg_id = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(
            msg_send_addr
        )
        msg_void = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)(msg_send_addr)
        msg_nsstr = ctypes.CFUNCTYPE(
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p
        )(msg_send_addr)
        msg_can_eval = ctypes.CFUNCTYPE(
            ctypes.c_bool,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_long,
            ctypes.POINTER(ctypes.c_void_p),
        )(msg_send_addr)
        msg_eval = ctypes.CFUNCTYPE(
            None,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_long,
            ctypes.c_void_p,
            ctypes.c_void_p,
        )(msg_send_addr)

        la_cls = objc.objc_getClass(b"LAContext")
        nsstr_cls = objc.objc_getClass(b"NSString")
        if not la_cls or not nsstr_cls:
            return None

        sel_alloc = objc.sel_registerName(b"alloc")
        sel_init = objc.sel_registerName(b"init")
        sel_release = objc.sel_registerName(b"release")
        sel_utf8 = objc.sel_registerName(b"stringWithUTF8String:")
        sel_can_eval = objc.sel_registerName(b"canEvaluatePolicy:error:")
        sel_eval = objc.sel_registerName(b"evaluatePolicy:localizedReason:reply:")

        ctx_raw = msg_id(la_cls, sel_alloc)
        ctx = msg_id(ctx_raw, sel_init) if ctx_raw else None
        if not ctx:
            return None

        try:
            err_ptr = ctypes.c_void_p(0)
            can_eval = msg_can_eval(
                ctx,
                sel_can_eval,
                _LA_POLICY_DEVICE_OWNER_AUTH,
                ctypes.byref(err_ptr),
            )
            if not can_eval:
                return None

            reason_bytes = (reason or "Authenticate to access passkey secrets").encode("utf-8")
            ns_reason = msg_nsstr(nsstr_cls, sel_utf8, reason_bytes)
            if not ns_reason:
                return None

            done = threading.Event()
            outcome: list[bool] = []

            InvokeFn = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_bool, ctypes.c_void_p)

            class _BlockDescriptor(ctypes.Structure):
                _fields_ = [
                    ("reserved", ctypes.c_ulong),
                    ("size", ctypes.c_ulong),
                ]

            class _ObjCBlock(ctypes.Structure):
                _fields_ = [
                    ("isa", ctypes.c_void_p),
                    ("flags", ctypes.c_int),
                    ("reserved", ctypes.c_int),
                    ("invoke", InvokeFn),
                    ("descriptor", ctypes.POINTER(_BlockDescriptor)),
                ]

            def _reply_callback(_block_ptr, success: bool, _error_ptr) -> None:
                outcome.append(bool(success))
                done.set()

            c_callback = InvokeFn(_reply_callback)
            descriptor = _BlockDescriptor(0, ctypes.sizeof(_ObjCBlock))
            stack_block_sym = ctypes.c_void_p.in_dll(libc, "_NSConcreteStackBlock")
            block = _ObjCBlock(
                ctypes.addressof(stack_block_sym),
                0,
                0,
                c_callback,
                ctypes.pointer(descriptor),
            )

            msg_eval(
                ctx,
                sel_eval,
                _LA_POLICY_DEVICE_OWNER_AUTH,
                ns_reason,
                ctypes.cast(ctypes.byref(block), ctypes.c_void_p),
            )

            if not done.wait(timeout=timeout):
                return False
            # Brief grace so XPC reply thread exits callback frame cleanly
            time.sleep(0.01)
            return bool(outcome and outcome[0])
        finally:
            msg_void(ctx, sel_release)
    except Exception:
        return None


def _authenticate_macOS(reason: str = "Authenticate to access secrets") -> bool:
    """Trigger macOS authentication via LocalAuthentication (Touch ID / Watch) or sudo -v."""
    if _lacontext_enabled():
        la_result = _evaluate_lacontext(reason)
        if la_result is not None:
            return la_result

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
    """Trigger Linux polkit authentication dialog."""
    try:
        result = subprocess.run(
            ["/usr/bin/pkexec", "/usr/bin/true"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return _authenticate_sudo_fallback()
    except subprocess.TimeoutExpired:
        return False


def _authenticate_windows() -> bool:
    """Honest no-op on Windows (relies on Credential Manager ACLs)."""
    print(
        "Note: OS-auth prompts are not supported on Windows; "
        "relying on Credential Manager access controls.",
        file=sys.stderr,
    )
    return True


def _authenticate_sudo_fallback() -> bool:
    """Fallback: use getpass + sudo -S to verify user password."""
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
    """Trigger OS-level authentication."""
    if sys.platform == "darwin":
        # Preserve 0-arg call compatibility for existing mocks on _authenticate_macOS
        try:
            return _authenticate_macOS(reason)
        except TypeError:
            return _authenticate_macOS()
    elif sys.platform == "linux":
        return _authenticate_linux()
    elif sys.platform == "win32":
        return _authenticate_windows()
    else:
        return _authenticate_sudo_fallback()


def require_auth(operation: str = "access secrets") -> None:
    """Require authentication or raise PasskeyError."""
    if not authenticate(f"Passkey: {operation}"):
        raise PasskeyError(
            f"Authentication required to {operation}. Authentication failed or was cancelled.",
            error_code="BIOMETRIC_DENIED",
        )
