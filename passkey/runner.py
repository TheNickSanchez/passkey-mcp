"""Environment variable injection for subprocess execution."""

import os
import selectors
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from .audit import log_operation
from .interactive import is_agent_subprocess
from .keychain import PasskeyError, _get_entry, get_entry
from .masking import SecretMasker
from .models import Entry
from .references import is_reference, parse_dotenv_file, parse_reference, resolve_reference

_SELECT_POLL_SECONDS = 0.1
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
            events = sel.select(timeout=_SELECT_POLL_SECONDS)
            if not events:
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


def _check_executable(executable: str) -> bool:
    """Return True if executable exists as an explicit path or via PATH."""
    if os.sep in executable or (os.altsep and os.altsep in executable):
        candidate = Path(executable).expanduser()
        return candidate.is_file() and os.access(candidate, os.X_OK)
    return shutil.which(executable) is not None


def preflight_run(
    entries: list[str],
    command: list[str] | None = None,
    *,
    env_files: list[str] | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict:
    """Validate entries, env-files, references, leases, and command without exposing values."""
    from .leases import peek_all_leases

    active_leases = peek_all_leases()
    entry_cache: dict[str, Entry | None] = {}
    entries_found: list[dict] = []
    entries_missing: list[str] = []
    injected_vars: set[str] = set()
    prompt_without_lease: set[str] = set()
    remediation: list[str] = []

    # Build an interpolation-only env map (never copied into output)
    interp_env = os.environ.copy()
    if extra_env:
        interp_env.update(extra_env)

    for name in entries:
        entry = _get_entry(name, log_read=False)
        entry_cache[name] = entry
        if entry is None:
            entries_missing.append(name)
            remediation.append(
                f"Ask the user to run 'passkey new {name}' in their terminal "
                "(never ask them to paste secrets into chat)."
            )
            continue

        has_lease = name in active_leases
        policy = getattr(entry, "policy", "allow")
        will_prompt = policy == "prompt" and not has_lease
        if will_prompt:
            prompt_without_lease.add(name)

        secret_keys = sorted(entry.fields.keys())
        config_keys = sorted(entry.config.keys())
        injected_vars.update(secret_keys)
        injected_vars.update(config_keys)
        # Non-secret config values may participate in $VAR interpolation; never expose in output
        interp_env.update(entry.config)

        entries_found.append(
            {
                "name": name,
                "policy": policy,
                "has_active_lease": has_lease,
                "will_prompt_biometric": will_prompt,
                "secret_keys": secret_keys,
                "config_keys": config_keys,
            }
        )

    env_files_list = list(env_files or [])
    env_files_missing: list[str] = []
    dotenv_entries: dict[str, str] = {}
    for ef in env_files_list:
        try:
            parsed = parse_dotenv_file(Path(ef))
            dotenv_entries.update(parsed)
            injected_vars.update(parsed.keys())
            for k, v in parsed.items():
                if not is_reference(v):
                    interp_env[k] = v
        except PasskeyError as e:
            env_files_missing.append(str(ef))
            remediation.append(str(e))

    # Collect candidate passkey:// references across inherited env, extra_env, and dotenv files
    merged_candidates: dict[str, str] = {}
    for k, v in os.environ.items():
        if is_reference(v):
            merged_candidates[k] = v
    if extra_env:
        for k, v in extra_env.items():
            if is_reference(v):
                merged_candidates[k] = v
    for k, v in dotenv_entries.items():
        if is_reference(v):
            merged_candidates[k] = v

    references_valid: list[dict] = []
    references_invalid: list[dict] = []

    for env_var in sorted(merged_candidates):
        uri = merged_candidates[env_var]
        try:
            ref_entry_name, ref_field = parse_reference(uri, env=interp_env)
        except PasskeyError as e:
            references_invalid.append(
                {"env_var": env_var, "reference": uri, "reason": str(e)}
            )
            continue

        if ref_entry_name not in entry_cache:
            entry_cache[ref_entry_name] = _get_entry(ref_entry_name, log_read=False)
        ref_entry = entry_cache[ref_entry_name]
        if ref_entry is None:
            references_invalid.append(
                {
                    "env_var": env_var,
                    "reference": uri,
                    "reason": f"entry '{ref_entry_name}' not found",
                }
            )
            remediation.append(
                f"Ask the user to run 'passkey new {ref_entry_name}' in their terminal."
            )
            continue

        ref_policy = getattr(ref_entry, "policy", "allow")
        ref_has_lease = ref_entry_name in active_leases
        if ref_policy == "prompt" and not ref_has_lease:
            prompt_without_lease.add(ref_entry_name)

        if ref_field in ref_entry.fields:
            injected_vars.add(env_var)
            references_valid.append(
                {
                    "env_var": env_var,
                    "reference": uri,
                    "entry": ref_entry_name,
                    "field": ref_field,
                    "kind": "secret",
                }
            )
        elif ref_field in ref_entry.config:
            injected_vars.add(env_var)
            references_valid.append(
                {
                    "env_var": env_var,
                    "reference": uri,
                    "entry": ref_entry_name,
                    "field": ref_field,
                    "kind": "config",
                }
            )
        else:
            references_invalid.append(
                {
                    "env_var": env_var,
                    "reference": uri,
                    "reason": f"field '{ref_field}' not found in entry '{ref_entry_name}'",
                }
            )
            remediation.append(
                f"Ask the user to run 'passkey entry set-field {ref_entry_name} {ref_field}' "
                "in their terminal."
            )

    for pname in sorted(prompt_without_lease):
        remediation.append(
            f"Entry '{pname}' requires Touch ID/OS auth; ask the user to grant a temporary "
            f"lease with 'passkey lease grant {pname} --ttl 15m'."
        )

    cmd_list = list(command) if command else None
    cmd_exec_found: bool | None = None
    if cmd_list:
        cmd_exec_found = _check_executable(cmd_list[0])
        if not cmd_exec_found:
            remediation.append(f"Command executable '{cmd_list[0]}' was not found in PATH.")

    has_any_source = bool(entries_found or references_valid or (env_files_list and not env_files_missing))
    if not has_any_source and not entries_missing and not references_invalid and not env_files_missing:
        remediation.append(
            "No entries or passkey:// references specified for 'passkey run'."
        )

    # Deduplicate remediation hints while preserving order
    deduped_remediation = list(dict.fromkeys(remediation))

    ready = (
        has_any_source
        and not entries_missing
        and not env_files_missing
        and not references_invalid
        and (cmd_exec_found is None or cmd_exec_found is True)
    )

    return {
        "ready": ready,
        "entries_requested": list(entries),
        "entries_found": entries_found,
        "entries_missing": entries_missing,
        "env_files": env_files_list,
        "env_files_missing": env_files_missing,
        "references_checked": len(merged_candidates),
        "references_valid": references_valid,
        "references_invalid": references_invalid,
        "injected_env_vars": sorted(injected_vars),
        "prompt_entries_without_lease": sorted(prompt_without_lease),
        "will_prompt_biometric": bool(prompt_without_lease),
        "command": cmd_list,
        "command_executable_found": cmd_exec_found,
        "remediation": deduped_remediation,
    }


def run_with_secrets(
    entries: list[str],
    command: list[str],
    *,
    no_masking: bool = False,
    quiet: bool = False,
    strict: bool = False,
    env_files: list[str] | None = None,
    extra_env: dict[str, str] | None = None,
    authorize_fn: Callable[[Entry], None] | None = None,
) -> int:
    """Run command with secrets, --env-file mappings, and passkey:// references injected."""
    suppress_banner = quiet or is_agent_subprocess()
    if not suppress_banner:
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
                if strict:
                    raise PasskeyError(
                        f"Entry '{name}' not found (--strict). "
                        f"Ask the user to run 'passkey new {name}' in their terminal "
                        "(never ask them to paste secrets into chat).",
                        error_code="ENTRY_NOT_FOUND",
                        entry=name,
                        remediation_command=f"passkey new {name}",
                    )
                if not quiet:
                    print(
                        f"Warning: Entry '{name}' not found, skipping "
                        f"(create with 'passkey new {name}')",
                        file=sys.stderr,
                    )

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
        raise PasskeyError(
            f"Failed to load secrets: {e}",
            error_code=e.error_code,
            entry=e.entry,
            missing_fields=e.missing_fields,
            remediation_command=e.remediation_command,
        ) from e

    if loaded_count == 0 and resolved_references == 0 and not env_files:
        first_entry = entries[0] if entries else None
        hint = (
            f" Ask the user to run 'passkey new {first_entry}' in their terminal "
            "(never paste secrets into chat)."
            if first_entry
            else ""
        )
        raise PasskeyError(
            f"No entries loaded, aborting command.{hint}",
            error_code="ENTRY_NOT_FOUND" if first_entry else "NO_SECRETS_LOADED",
            entry=first_entry,
            remediation_command=f"passkey new {first_entry}" if first_entry else None,
        )

    if not command:
        raise PasskeyError("No command specified to run.", error_code="INVALID_USAGE")

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
        raise PasskeyError(
            f"Command not found: '{command[0]}'",
            error_code="COMMAND_NOT_FOUND",
        ) from None
    except OSError as e:
        raise PasskeyError(f"Failed to execute command: {e}") from e
