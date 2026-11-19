"""Ephemeral UNIX FIFO (.env) secret mounter."""

import contextlib
import errno
import os
import signal
import stat
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from .audit import log_operation
from .commands import fields_as_env
from .interactive import InteractiveRequiredError, can_prompt_interactively
from .keychain import PasskeyError, _get_entry
from .mcp_config import is_file_exposed_in_git
from .models import Entry


class _MountInterrupted(BaseException):
    """Internal signal to break cleanly out of a blocking FIFO open()."""


def _open_fifo_writer(fifo_path: Path, *, timeout: float | None) -> int:
    """Open FIFO for writing, optionally enforcing a bounded reader wait timeout."""
    if timeout is None:
        return os.open(fifo_path, os.O_WRONLY)

    import fcntl

    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)
            return fd
        except OSError as e:
            if e.errno != errno.ENXIO:
                raise PasskeyError(f"Failed to open FIFO '{fifo_path}': {e}") from e
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PasskeyError(
                    f"Timed out after {timeout:g}s waiting for a reader on FIFO '{fifo_path}'.",
                    error_code="MOUNT_TIMEOUT",
                ) from None
            time.sleep(min(0.02, max(0.001, remaining)))


def mount_env_fifo(
    entries: list[str],
    path: str | Path = ".env",
    *,
    max_reads: int | None = None,
    timeout: float | None = None,
    force_git_exposed: bool = False,
    quiet: bool = False,
    authorize_fn: Callable[[Entry], None] | None = None,
) -> int:
    """Mount an ephemeral 0o600 POSIX FIFO at path that streams KEY='value' lines on read.

    Secrets never touch disk blocks; the kernel pipe buffer transfers bytes
    directly to the reader process, and the FIFO node is unlinked on exit.
    """
    if sys.platform == "win32" or not hasattr(os, "mkfifo"):
        raise PasskeyError(
            "Ephemeral FIFO mounting ('passkey mount') requires POSIX named pipes "
            "(macOS or Linux) and is not supported on Windows. Use 'passkey run' instead."
        )

    if not entries:
        raise PasskeyError("At least one passkey entry is required for 'passkey mount'.")

    if timeout is not None and timeout <= 0:
        raise PasskeyError("--timeout must be greater than 0 seconds.")

    if max_reads is not None and max_reads <= 0:
        raise PasskeyError("--max-reads must be at least 1.")

    if not can_prompt_interactively() and max_reads is None and timeout is None:
        joined = " ".join(entries)
        raise InteractiveRequiredError(
            f"'passkey mount' without --once, --max-reads, or --timeout blocks indefinitely "
            f"in non-interactive sessions. "
            f"For single-command execution use 'passkey run -q {joined} -- <command>' or "
            f"'passkey run -q --env-file .env.passkey -- <command>', or bound the FIFO with "
            f"'passkey mount --once --timeout 30 {joined}'.",
            error_code="INTERACTIVE_REQUIRED",
            remediation_command=f"passkey run -q {joined} -- <command>",
        )

    fifo_path = Path(path).expanduser()
    if fifo_path.exists() or fifo_path.is_symlink():
        with contextlib.suppress(OSError):
            if stat.S_ISFIFO(fifo_path.lstat().st_mode):
                raise PasskeyError(
                    f"FIFO already exists at '{fifo_path}'. Another 'passkey mount' may be "
                    f"running; if it is stale, remove it with: rm '{fifo_path}'"
                )
        raise PasskeyError(
            f"Refusing to mount FIFO at '{fifo_path}': file already exists. Remove it first."
        )

    if not force_git_exposed and is_file_exposed_in_git(fifo_path):
        raise PasskeyError(
            f"Refusing to mount FIFO at '{fifo_path}': target path is inside a git repository "
            f"and is not gitignored. Add '{fifo_path.name}' to .gitignore first."
        )

    # Validate upfront that at least one entry exists
    initial_found = False
    for name in entries:
        ent = _get_entry(name, log_read=False)
        if ent is not None:
            initial_found = True
    if not initial_found:
        raise PasskeyError("No matching entries found in keychain for mount.")

    if authorize_fn is None:
        from .leases import authorize_entry_access

        authorize_fn = authorize_entry_access

    fifo_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkfifo(fifo_path, 0o600)
        fifo_path.chmod(0o600)
    except OSError as e:
        raise PasskeyError(f"Failed to create FIFO at '{fifo_path}': {e}") from e

    is_main_thread = threading.current_thread() is threading.main_thread()
    prev_sigint = None
    prev_sigterm = None

    def _handle_stop(signum, frame):
        raise _MountInterrupted()

    if is_main_thread:
        prev_sigint = signal.signal(signal.SIGINT, _handle_stop)
        prev_sigterm = signal.signal(signal.SIGTERM, _handle_stop)

    reads = 0
    log_operation("mount_start", details={"entries": entries, "path": str(fifo_path)})
    if not quiet:
        print(
            f"Mounted ephemeral FIFO at {fifo_path} for {', '.join(entries)} (Ctrl+C to unmount)",
            file=sys.stderr,
        )

    try:
        while max_reads is None or reads < max_reads:
            fd = _open_fifo_writer(fifo_path, timeout=timeout)
            try:
                combined: dict[str, str] = {}
                for name in entries:
                    entry = _get_entry(name, log_read=False)
                    if entry is not None:
                        if authorize_fn is not None:
                            authorize_fn(entry)
                        combined.update(entry.get_all_env_vars())
                payload = (fields_as_env(combined) + "\n").encode("utf-8") if combined else b""
                view = memoryview(payload)
                written = 0
                while written < len(view):
                    written += os.write(fd, view[written:])
            except BrokenPipeError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    os.close(fd)

            reads += 1
            log_operation(
                "mount_read",
                details={"entries": entries, "path": str(fifo_path), "read_count": reads},
            )
            if max_reads is None or reads < max_reads:
                # Brief yield so current reader closes its descriptor before we reopen O_WRONLY
                time.sleep(0.01)
    except _MountInterrupted:
        if not quiet:
            print(f"\nUnmounted {fifo_path}", file=sys.stderr)
    finally:
        if is_main_thread:
            if prev_sigint is not None:
                signal.signal(signal.SIGINT, prev_sigint)
            if prev_sigterm is not None:
                signal.signal(signal.SIGTERM, prev_sigterm)
        with contextlib.suppress(OSError):
            fifo_path.unlink()
        log_operation("mount_stop", details={"path": str(fifo_path), "reads_served": reads})

    return reads
