"""Environment variable injection for subprocess execution."""

import os
import selectors
import subprocess
import sys

from .keychain import PasskeyError, get_entry
from .masking import SecretMasker

_IDLE_FLUSH_SECONDS = 0.005
_READ_CHUNK_BYTES = 4096


def _write_stream_bytes(stream, data: bytes) -> None:
    """Write raw bytes to a standard stream, supporting both binary buffers and text mocks."""
    if not data:
        return
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        buf.write(data)
        buf.flush()
    else:
        stream.write(data.decode("utf-8", errors="replace"))
        stream.flush()


def _run_masked_subprocess(command: list[str], env: dict[str, str], secret_values: list[str]) -> int:
    """Execute command while scrubbing secret_values from child stdout and stderr."""
    stdout_masker = SecretMasker(secret_values)
    stderr_masker = SecretMasker(secret_values)

    proc = subprocess.Popen(
        command,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert proc.stdout is not None
    assert proc.stderr is not None

    sel = selectors.DefaultSelector()
    stream_map = {
        proc.stdout.fileno(): (proc.stdout, stdout_masker, sys.stdout),
        proc.stderr.fileno(): (proc.stderr, stderr_masker, sys.stderr),
    }

    for fd in list(stream_map):
        sel.register(fd, selectors.EVENT_READ)

    try:
        while sel.get_map():
            events = sel.select(timeout=_IDLE_FLUSH_SECONDS)
            if not events:
                # Short idle window: flush held-back partial prefix bytes so prompts/frames never stall.
                for _, masker, target in stream_map.values():
                    flushed = masker.flush()
                    if flushed:
                        _write_stream_bytes(target, flushed)
                if proc.poll() is not None and not sel.get_map():
                    break
                continue

            for key, _ in events:
                fd = key.fd
                pipe_obj, masker, target = stream_map[fd]
                try:
                    chunk = os.read(fd, _READ_CHUNK_BYTES)
                except OSError:
                    chunk = b""

                if not chunk:
                    sel.unregister(fd)
                    pipe_obj.close()
                    tail = masker.flush()
                    if tail:
                        _write_stream_bytes(target, tail)
                else:
                    out = masker.feed(chunk)
                    if out:
                        _write_stream_bytes(target, out)
    finally:
        sel.close()
        for pipe_obj, _, _ in stream_map.values():
            if not pipe_obj.closed:
                pipe_obj.close()

    return proc.wait()


def run_with_secrets(
    entries: list[str],
    command: list[str],
    *,
    no_masking: bool = False,
    quiet: bool = False,
) -> int:
    """Run command with secrets and config from entries as environment variables.

    Args:
        entries: List of entry names to load
        command: Command and arguments to execute
        no_masking: Disable real-time secret masking on child stdout/stderr
        quiet: Suppress passkey status/warning messages on stderr

    Returns:
        The command's exit code (the CLI layer owns sys.exit).

    Raises:
        PasskeyError: If entries cannot be loaded or the command fails to start.

    Note:
        If multiple entries contain the same field name,
        later entries override earlier ones.
    """
    if not quiet:
        warning = (
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! SECURITY WARNING !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
            "Injecting secrets as environment variables can expose them to other processes\n"
            "on this system. Use this feature with caution, especially for long-lived\n"
            "processes. Prefer tools that accept secrets via stdin or other mechanisms.\n"
            "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        )
        print(warning, file=sys.stderr)

    env = os.environ.copy()
    loaded_count = 0
    secret_values: list[str] = []

    try:
        for name in entries:
            entry = get_entry(name)
            if entry:
                all_vars = entry.get_all_env_vars()
                env.update(all_vars)
                secret_values.extend(entry.fields.values())
                loaded_count += 1
                secret_count = len(entry.fields)
                if not quiet:
                    print(
                        f"Loaded {secret_count} secret(s) from '{name}' into environment",
                        file=sys.stderr,
                    )
            else:
                if not quiet:
                    print(f"Warning: Entry '{name}' not found, skipping", file=sys.stderr)
    except PasskeyError as e:
        raise PasskeyError(f"Failed to load secrets: {e}") from e

    if loaded_count == 0:
        raise PasskeyError("No entries loaded, aborting command.")

    if not command:
        raise PasskeyError("No command specified to run.")

    try:
        if no_masking:
            result = subprocess.run(command, env=env)
            return result.returncode
        return _run_masked_subprocess(command, env, secret_values)
    except FileNotFoundError:
        raise PasskeyError(f"Command not found: '{command[0]}'") from None
    except OSError as e:
        raise PasskeyError(f"Failed to execute command: {e}") from e
