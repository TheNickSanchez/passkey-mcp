"""Environment variable injection for subprocess execution."""

import os
import selectors
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from .audit import log_operation
from .keychain import PasskeyError, get_entry
from .masking import SecretMasker
from .models import Entry
from .references import is_reference, parse_dotenv_file, resolve_reference

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


def _run_masked_subprocess(
    command: list[str], env: dict[str, str], secret_values: list[str]
) -> int:
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
    env_files: list[str] | None = None,
    extra_env: dict[str, str] | None = None,
    authorize_fn: Callable[[Entry], None] | None = None,
) -> int:
    """Run command with secrets, --env-file mappings, and passkey:// references injected."""
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
    if extra_env:
        env.update(extra_env)

    loaded_count = 0
    secret_values: list[str] = []
    entry_cache: dict[str, Entry | None] = {}
    if authorize_fn is None:
        from .leases import authorize_entry_access

        authorize_fn = authorize_entry_access

    try:
        for name in entries:
            entry = get_entry(name)
            entry_cache[name] = entry
            if entry:
                if authorize_fn is not None:
                    authorize_fn(entry)
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

        for ef in env_files or []:
            parsed_env = parse_dotenv_file(Path(ef))
            env.update(parsed_env)

        # Resolve any passkey://<entry>/<field> references in env (from inherited env, MCP config, or --env-file)
        resolved_references = 0
        for key, val in list(env.items()):
            if is_reference(val):
                resolved_val, is_sec = resolve_reference(
                    val,
                    env=env,
                    entry_cache=entry_cache,
                    authorize_fn=authorize_fn,
                    log_read=True,
                )
                env[key] = resolved_val
                if is_sec:
                    secret_values.append(resolved_val)
                resolved_references += 1
    except PasskeyError as e:
        raise PasskeyError(f"Failed to load secrets: {e}") from e

    if loaded_count == 0 and resolved_references == 0 and not env_files:
        raise PasskeyError("No entries loaded, aborting command.")

    if not command:
        raise PasskeyError("No command specified to run.")

    log_operation(
        "run",
        entry_name=entries[0] if len(entries) == 1 else None,
        details={
            "entries": entries,
            "resolved_references": resolved_references,
        },
        argv0=command[0],
    )

    try:
        if no_masking:
            result = subprocess.run(command, env=env)
            return result.returncode
        return _run_masked_subprocess(command, env, secret_values)
    except FileNotFoundError:
        raise PasskeyError(f"Command not found: '{command[0]}'") from None
    except OSError as e:
        raise PasskeyError(f"Failed to execute command: {e}") from e
