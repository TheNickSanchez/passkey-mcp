"""Passkey MCP Server - Expose passkey tools to AI coding assistants.

This MCP server allows LLMs to discover and use passkey entries.
Importantly, secret VALUES are never exposed through the MCP protocol -
LLMs can only inject secrets via 'passkey run', never read them.
"""

import re as _re
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .keychain import PasskeyError, _get_entry, get_entry, list_entries
from .mcp_config import (
    ADAPTERS,
    MCPConfigError,
    find_adapter_for_path,
    get_mcp_servers,
    get_server_security_status,
    is_passkey_wrapped,
    load_config,
    rewrite_server_for_passkey,
    save_config,
)

MCP_INSTRUCTIONS = (
    "passkey manages developer secrets in the OS keychain so secret VALUES never enter "
    "AI context, stdout, or plaintext files. "
    "Golden rules for AI agents: "
    "(1) Inspect metadata first with passkey_entry_info or passkey_preflight_run to verify "
    "field names, config_keys, policy ('allow' vs 'prompt'), and has_active_lease. "
    "(2) Inject secrets into subprocesses via 'passkey run -q <entry> -- <command>' or render "
    "gitignored templates via 'passkey inject -i <tpl> -o <outfile>'. "
    "(3) Never run interactive commands ('passkey', 'passkey get', 'passkey new', 'passkey edit') "
    "and NEVER ask the human user to paste raw API keys or tokens into chat—instruct them to run "
    "'passkey new <name>' or 'passkey lease grant <name> --ttl 15m' in their own terminal."
)

_READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_CONFIG_MUTATING_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
_BROWSER_MUTATING_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)

_FORBIDDEN_SYSTEM_PREFIXES = (
    "/etc/",
    "/private/etc/",
    "/dev/",
    "/proc/",
    "/sys/",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/lib/",
    "/boot/",
    "/var/root/",
    "/private/var/",
    "/System/",
)

# Initialize MCP server
mcp = FastMCP(name="passkey", instructions=MCP_INSTRUCTIONS)


def _is_forbidden_system_path(raw_path: str) -> tuple[bool, Path]:
    """Return (is_forbidden, resolved_path) blocking sensitive OS paths."""
    expanded = Path(raw_path).expanduser()
    resolved = expanded.resolve()
    resolved_str = str(resolved)
    if resolved_str.startswith("/private/var/folders/"):
        return False, resolved
    exp_check = str(expanded).rstrip("/") + "/"
    res_check = resolved_str.rstrip("/") + "/"
    if exp_check.startswith(_FORBIDDEN_SYSTEM_PREFIXES) or res_check.startswith(
        _FORBIDDEN_SYSTEM_PREFIXES
    ):
        return True, resolved
    return False, resolved


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_list() -> list[str]:
    """List all available passkey entries.

    Returns the names of all secret entries stored in the system keychain.
    Each entry can contain multiple key-value secret pairs.

    Returns:
        List of entry names (e.g., ["slack", "github", "aws"])
    """
    try:
        return list_entries()
    except PasskeyError as e:
        raise Exception(f"Failed to access keychain: {e}") from e


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_fields(entry_name: str) -> list[str]:
    """List field names in a passkey entry (without revealing values or logging a secret read).

    Returns the names of secret fields stored in the specified entry.
    Prefer ``passkey_entry_info`` when you also need ``config_keys``, ``policy``,
    and ``has_active_lease``.

    Args:
        entry_name: Name of the passkey entry (e.g., "slack")

    Returns:
        List of field names (e.g., ["SLACK_TOKEN", "SLACK_COOKIE"])

    Raises:
        Exception: If entry not found or keychain access fails
    """
    try:
        entry = _get_entry(entry_name, log_read=False)
        if entry is None:
            safe = _sanitize(entry_name)
            raise Exception(
                f"Entry '{safe}' not found. Ask the user to run 'passkey new {safe}' "
                "in their terminal (never ask them to paste secrets into chat)."
            )
        return list(entry.fields.keys())
    except PasskeyError as e:
        raise Exception(f"Failed to access keychain: {e}") from e


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_entry_info(entry_name: str) -> dict:
    """Inspect complete non-sensitive metadata for a passkey entry without exposing values.

    Read-only: never triggers Touch ID, never decrements active lease uses,
    and never exposes secret or config values.

    Args:
        entry_name: Name of the passkey entry (e.g., "stripe")

    Returns:
        Dictionary with exists, policy ('allow' or 'prompt'), has_active_lease,
        will_prompt_biometric, fields (secret key names), config_keys, and timestamps.
    """
    from .leases import peek_lease

    safe = _sanitize(entry_name)
    try:
        entry = _get_entry(entry_name, log_read=False)
    except PasskeyError as e:
        raise Exception(f"Failed to access keychain: {e}") from e

    if entry is None:
        return {
            "exists": False,
            "name": safe,
            "remediation": (
                f"Ask the user to run 'passkey new {safe}' in their terminal "
                "(never ask them to paste secrets into chat)."
            ),
        }

    lease = peek_lease(entry.name, allow_session=(entry.policy != "prompt"))
    has_lease = lease is not None
    secret_keys = sorted(entry.fields.keys())
    config_keys = sorted(entry.config.keys())

    return {
        "exists": True,
        "name": entry.name,
        "policy": entry.policy,
        "has_active_lease": has_lease,
        "lease_seconds_remaining": lease["seconds_remaining"] if lease else None,
        "lease_remaining_uses": lease.get("remaining_uses") if lease else None,
        "will_prompt_biometric": entry.policy in ("prompt", "session") and not has_lease,
        "fields": secret_keys,
        "config_keys": config_keys,
        "field_count": len(secret_keys),
        "config_count": len(config_keys),
        "created": entry.created,
        "modified": entry.modified,
        "last_rotated": entry.last_rotated,
        "source": entry.source,
    }


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_find(
    vars: list[str] | None = None,
    from_file: str | None = None,
) -> dict:
    """Reverse-lookup which passkey entries store given environment variable names.

    Matches exact names, service-specific aliases (e.g., GH_TOKEN <-> GITHUB_TOKEN),
    and entry-scoped generic fields (e.g., RESEND_API_KEY -> resend/API_KEY) across
    both secret fields and config keys without reading or exposing values.

    Args:
        vars: Environment variable names to find (e.g., ["RESEND_API_KEY", "GH_TOKEN"])
        from_file: Optional path to a safe template file (e.g., ".env.example")

    Returns:
        Dictionary with matches, results, resolved_entries, missing_vars, and suggested_run_command.
    """
    from .find import find_env_vars
    from .hooks import is_sensitive_secret_path

    safe_file: Path | None = None
    if from_file is not None:
        if is_sensitive_secret_path(from_file):
            return {
                "ok": False,
                "error_code": "SENSITIVE_FILE_REFUSED",
                "message": (
                    f"Refusing to read sensitive secret file '{_sanitize(from_file)}'. "
                    "Pass '.env.example' or '.env.template' instead."
                ),
                "missing_vars": [],
            }
        forbidden, resolved = _is_forbidden_system_path(from_file)
        if forbidden:
            return {
                "ok": False,
                "error_code": "FORBIDDEN_PATH",
                "message": "Access to system path denied.",
                "missing_vars": [],
            }
        safe_file = resolved

    try:
        return find_env_vars(vars, from_file=safe_file)
    except PasskeyError as e:
        return e.to_error_dict()


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_preflight_run(
    entries: list[str],
    env_files: list[str] | None = None,
    command: list[str] | None = None,
) -> dict:
    """Dry-run preflight for ``passkey run`` without spawning a process or exposing values.

    Validates that all requested entries, ``--env-file`` mappings, ``passkey://``
    references, active leases, and optional command executable are ready.

    Args:
        entries: Entry names to inject (e.g., ["stripe", "github"])
        env_files: Optional dotenv/reference files to validate
        command: Optional command argv to verify executable availability

    Returns:
        Secret-free preflight dictionary with ready, injected_env_vars,
        entries_missing, will_prompt_biometric, and remediation steps.
    """
    from .runner import preflight_run

    safe_env_files: list[str] = []
    for ef in env_files or []:
        forbidden, resolved = _is_forbidden_system_path(ef)
        if forbidden:
            return {
                "ready": False,
                "entries_requested": list(entries),
                "entries_found": [],
                "entries_missing": [],
                "env_files": list(env_files or []),
                "env_files_missing": [ef],
                "references_checked": 0,
                "references_valid": [],
                "references_invalid": [],
                "injected_env_vars": [],
                "prompt_entries_without_lease": [],
                "will_prompt_biometric": False,
                "command": list(command) if command else None,
                "command_executable_found": None,
                "remediation": ["Access to system path denied."],
            }
        safe_env_files.append(str(resolved))

    try:
        return preflight_run(entries, command=command, env_files=safe_env_files)
    except PasskeyError as e:
        raise Exception(f"Preflight check failed: {e}") from e


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_project_status(
    project_dir: str = ".",
    command: list[str] | None = None,
) -> dict:
    """Inspect repo secret manifest (.env.passkey / .passkey.toml), HMAC trust, and readiness.

    Auto-discovers the project manifest up to the enclosing git root, verifies
    whether its SHA-256 digest is trusted in ``trusted_projects.json``, and
    preflights all referenced entries and ``passkey://`` URIs without exposing
    any secret values.

    Args:
        project_dir: Project directory to inspect (default: current directory)
        command: Optional command argv to verify executable availability

    Returns:
        Secret-free dictionary with manifest_found, trusted, trust_status,
        ready, injected_env_vars, will_prompt_biometric, and remediation steps.
    """
    from .project import get_project_status

    forbidden, resolved = _is_forbidden_system_path(project_dir)
    if forbidden:
        return {
            "ok": False,
            "error_code": "FORBIDDEN_PATH",
            "message": "Access to system path denied.",
            "manifest_found": False,
            "trusted": False,
            "ready": False,
        }

    try:
        return get_project_status(resolved, command=command)
    except PasskeyError as e:
        return e.to_error_dict()


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_status() -> dict:
    """Show security status of MCP servers across all detected tools.

    Analyzes configs for Claude, Gemini, VS Code, Cursor, OpenCode,
    Windsurf, Cline, and Zed to identify which MCP servers have their
    secrets secured via passkey and which still have credentials
    exposed in plaintext.

    Returns:
        Dictionary with per-tool server status and summary counts
    """
    results = []
    summary = {"secured": 0, "exposed": 0, "partial": 0, "no_secrets": 0}

    # Fetch entry names once, not per config
    try:
        passkey_entries = list_entries()
    except PasskeyError:
        passkey_entries = []

    for adapter_name, adapter in ADAPTERS.items():
        for config_path in adapter.get_all_existing_paths():
            try:
                config = load_config(config_path)
            except (FileNotFoundError, MCPConfigError):
                continue

            servers = get_mcp_servers(config, adapter)
            if not servers:
                continue

            for name, server_config in servers.items():
                status = get_server_security_status(name, server_config, passkey_entries, adapter)
                status["tool"] = adapter_name
                status["config_path"] = str(config_path)
                results.append(status)
                if status["status"] in summary:
                    summary[status["status"]] += 1

    return {
        "servers": results,
        "summary": summary,
    }


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_doctor(deep: bool = False) -> dict:
    """Run diagnostics on passkey and MCP configurations.

    Checks for common issues including:
    - Config file existence and validity for all detected tools
    - Passkey command availability in PATH
    - Keychain access permissions
    - MCP servers with missing passkey entries
    - MCP servers with exposed secrets
    - (deep=True) entry age analysis and bundle file permissions

    Args:
        deep: Include extended checks (entry age, bundle permissions)

    Returns:
        Dictionary with diagnostic results
    """
    from .doctor import run_diagnostics

    return run_diagnostics(deep=deep)


def _validate_config_paths(paths: list[str]) -> list[Path]:
    """Validate and resolve config paths, blocking system-sensitive locations.

    Allows paths ending with .json or .jsonc that are not in
    system-protected directories. Nonexistent paths are passed through
    so the caller can produce appropriate error messages.
    """
    resolved = []
    for p in paths:
        forbidden, pp = _is_forbidden_system_path(p)
        if forbidden or pp.suffix not in (".json", ".jsonc"):
            continue
        resolved.append(pp)
    return resolved


_SAFE_NAME = _re.compile(r"[^a-zA-Z0-9._\-\s]")


def _sanitize(s: str) -> str:
    """Strip characters unsafe for log/error output."""
    return _SAFE_NAME.sub("", s)


@mcp.tool(annotations=_CONFIG_MUTATING_ANNOTATIONS)
def passkey_request_secret(
    entry_name: str,
    fields: list[str],
    policy: str | None = None,
    hint: str | None = None,
    timeout: int = 120,
    overwrite: bool = False,
) -> dict:
    """Prompt the human user via an out-of-band native OS hidden dialog to save missing secrets.

    Opens a secure macOS/Linux password dialog directly on the user's desktop,
    stores the entered value(s) straight into the OS keychain, and returns only
    field names and status — secret values NEVER enter AI context or tool output.
    Automatically skips fields that already exist unless ``overwrite=True``.

    Args:
        entry_name: Keychain entry name to create or update (e.g., "stripe_dev")
        fields: Environment variable / field names to capture (max 10)
        policy: Optional access policy ('allow', 'session', or 'prompt')
        hint: Optional short hint shown in the dialog (e.g., where to find the key)
        timeout: Seconds to wait before timing out (5-300, default: 120)
        overwrite: Re-prompt even if requested fields already exist

    Returns:
        Secret-free dictionary with ok, status ('created'|'updated'|'already_exists'),
        entry, fields_saved, fields_present, and policy.
    """
    from .request_secret import request_secret
    from .settings import mcp_write_tools_enabled

    if not mcp_write_tools_enabled():
        return {
            "ok": False,
            "error_code": "MCP_WRITE_DISABLED",
            "message": (
                "MCP write tools are disabled by policy (mcp-write-tools = False). "
                "Enable with 'passkey config mcp-write-tools on' or ask the user to run "
                f"'passkey new {_sanitize(entry_name)}' in their terminal."
            ),
        }

    try:
        return request_secret(
            entry_name,
            fields,
            policy=policy,
            hint=hint,
            timeout=timeout,
            overwrite=overwrite,
        )
    except PasskeyError as e:
        return e.to_error_dict()


@mcp.tool(annotations=_CONFIG_MUTATING_ANNOTATIONS)
def passkey_wrap_server(
    server_name: str,
    config_paths: list[str] | None = None,
) -> dict:
    """Update MCP config files to use passkey wrapper for a server.

    Prerequisites: Entry must already exist in passkey keychain.

    Args:
        server_name: Name of the server (must match passkey entry)
        config_paths: Config files to update (default: all detected configs)

    Returns:
        - configs_updated: List of updated config paths
        - configs_skipped: List of configs where server not found
        - errors: Any errors encountered
    """
    from .settings import mcp_write_tools_enabled

    if not mcp_write_tools_enabled():
        return {
            "success": False,
            "message": (
                "MCP write tools are disabled by policy (mcp-write-tools = False). "
                "Enable with 'passkey config mcp-write-tools on' if intended."
            ),
        }

    try:
        entry = get_entry(server_name)
    except PasskeyError as e:
        return {"success": False, "message": f"Failed to access keychain: {e}"}

    if entry is None:
        return {
            "success": False,
            "message": f"Passkey entry '{_sanitize(server_name)}' not found. Use passkey new first.",
        }

    if config_paths:
        paths = _validate_config_paths(config_paths)
    else:
        paths = []
        for adapter in ADAPTERS.values():
            paths.extend(adapter.get_all_existing_paths())

    if not paths:
        return {"success": False, "message": "No config files found to update"}

    configs_updated, configs_skipped, errors = [], [], []

    for config_path in paths:
        try:
            config = load_config(config_path)
        except (FileNotFoundError, MCPConfigError) as e:
            errors.append(f"{config_path}: {e}")
            continue

        # Find the adapter for this path
        adapter = find_adapter_for_path(config_path)
        if not adapter:
            configs_skipped.append({"path": str(config_path), "reason": "unknown config format"})
            continue

        servers = get_mcp_servers(config, adapter)
        if server_name not in servers:
            configs_skipped.append({"path": str(config_path), "reason": "server not found"})
            continue

        if is_passkey_wrapped(servers[server_name]):
            configs_skipped.append({"path": str(config_path), "reason": "already wrapped"})
            continue

        servers[server_name] = rewrite_server_for_passkey(
            server_name, servers[server_name], adapter
        )

        try:
            save_config(config, config_path)
            configs_updated.append(str(config_path))
        except Exception as e:
            errors.append(f"{config_path}: {e}")

    return {
        "success": len(errors) == 0,
        "configs_updated": configs_updated,
        "configs_skipped": configs_skipped,
        "errors": errors,
    }


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_validate_references(file_path: str) -> dict:
    """Validate passkey://<entry>/<field> secret references in a template or env file.

    Checks whether every referenced entry and field exists in the keychain
    without exposing any secret values, and reports prompt-gated entries lacking a lease.

    Args:
        file_path: Path to a template or .env.passkey file containing passkey:// references

    Returns:
        Dictionary with {"valid": bool, "checked": int, "missing": [...], "prompt_entries_without_lease": [...]}
    """
    from .references import validate_references_in_file

    forbidden, resolved = _is_forbidden_system_path(file_path)
    if forbidden:
        return {
            "valid": False,
            "checked": 0,
            "missing": [{"reference": "", "reason": "Access to system path denied"}],
            "prompt_entries_without_lease": [],
            "will_prompt_biometric": False,
        }

    try:
        return validate_references_in_file(resolved)
    except PasskeyError as e:
        return {
            "valid": False,
            "checked": 0,
            "missing": [{"reference": "", "reason": str(e)}],
            "prompt_entries_without_lease": [],
            "will_prompt_biometric": False,
        }


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def passkey_audit_recent(limit: int = 20) -> list[dict]:
    """Return recent sanitized audit log records with caller attribution.

    Secret values and HMAC key material are never included.

    Args:
        limit: Maximum number of recent records to return (default: 20, max: 100)

    Returns:
        List of sanitized audit log entries (most recent first)
    """
    from .audit import get_sanitized_recent_logs

    return get_sanitized_recent_logs(limit=limit)


@mcp.tool(annotations=_BROWSER_MUTATING_ANNOTATIONS)
def passkey_cdp_autofill(entry_name: str, cdp_url: str) -> dict:
    """Deterministically fill credentials into a local Chrome DevTools browser tab.

    Disabled by default; enable explicitly via ``passkey config mcp-browser-broker on``.
    Verifies exact scheme + host + port match against the entry's ORIGIN config
    before touching any secret fields, and never returns secret values.

    Args:
        entry_name: Name of the passkey entry containing ORIGIN and credentials
        cdp_url: Loopback CDP WebSocket URL (e.g., ws://127.0.0.1:9222)

    Returns:
        Dictionary with {"filled": bool, "origin": str, "fields_injected": [...]}
    """
    from .browser_broker import cdp_autofill
    from .settings import mcp_browser_broker_enabled

    if not mcp_browser_broker_enabled():
        return {
            "filled": False,
            "message": (
                "MCP browser broker is disabled by default (mcp-browser-broker = False). "
                "Enable with 'passkey config mcp-browser-broker on'."
            ),
        }

    try:
        return cdp_autofill(entry_name, cdp_url)
    except PasskeyError as e:
        return {
            "filled": False,
            "message": str(e),
        }


@mcp.prompt(
    name="setup-project-secrets",
    description="Inspect project secret requirements and configure safe passkey runtime injection.",
)
def setup_project_secrets(project_dir: str = ".") -> str:
    """Guided workflow for wiring project credentials via passkey without exposing secrets."""
    safe_dir = _sanitize(project_dir) or "."
    return (
        f"Set up passkey secret injection for project directory '{safe_dir}' following these steps:\n"
        "1. Inspect safe templates in the repo (.env.example, .env.template, .env.passkey, .passkey.toml) "
        "— NEVER read .env, *.backup, or *.enc files.\n"
        "2. Call `passkey_list` and `passkey_entry_info` (or `passkey_validate_references` if a "
        "`.env.passkey` file exists) to check which entries and field names already exist.\n"
        "3. For any missing entry or field, NEVER ask the user to paste secret values in chat. "
        "Give the user the exact terminal command to run:\n"
        "   - `passkey new <entry>`\n"
        "   - `passkey entry set-field <entry> <FIELD_NAME>`\n"
        "4. Call `passkey_preflight_run` to verify `ready == true` and check `will_prompt_biometric`. "
        "If `will_prompt_biometric` is true, ask the user to run `passkey lease grant <entry> --ttl 15m`.\n"
        "5. Execute the target command with `passkey run -q --strict <entry> -- <command>`."
    )


@mcp.prompt(
    name="debug-missing-credential",
    description="Diagnose missing entries, missing fields, or Touch ID policy blocks for a passkey entry.",
)
def debug_missing_credential(entry_name: str, command: str = "") -> str:
    """Guided diagnostic playbook when a command fails due to missing or blocked secrets."""
    safe_entry = _sanitize(entry_name)
    safe_cmd = _sanitize(command)
    cmd_hint = f" for command `{safe_cmd}`" if safe_cmd else ""
    return (
        f"Diagnose credential availability for passkey entry '{safe_entry}'{cmd_hint}:\n"
        f"1. Call `passkey_entry_info(entry_name='{safe_entry}')`.\n"
        f"   - If `exists` is false, instruct the user to run `passkey new {safe_entry}` in their terminal.\n"
        "   - Inspect `fields` and `config_keys` to verify all expected environment variable names exist.\n"
        f"   - If `will_prompt_biometric` is true (`policy == 'prompt'` and no active lease), ask the user "
        f"to run `passkey lease grant {safe_entry} --ttl 15m` before headless execution.\n"
        f"2. Call `passkey_preflight_run(entries=['{safe_entry}'])` to verify end-to-end injection readiness.\n"
        "3. Call `passkey_doctor()` if keychain access or PATH resolution is failing.\n"
        "4. Security invariant: never request or echo raw secret values."
    )


@mcp.prompt(
    name="migrate-exposed-mcp-configs",
    description="Audit MCP client configs for plaintext secrets and guide migration to the OS keychain.",
)
def migrate_exposed_mcp_configs() -> str:
    """Guided workflow for auditing and securing plaintext MCP server configurations."""
    return (
        "Audit and secure MCP server configurations across installed AI tools:\n"
        "1. Call `passkey_status()` and `passkey_doctor()` to identify servers with `status == 'exposed'`, "
        "`'partial'`, or `'broken'`.\n"
        "2. Summarize exposed server names and secret key names (never secret values) by tool.\n"
        "3. Preview migration safely with `passkey init --dry-run --tool <tool>`, then instruct the user "
        "to run `passkey init --tool <tool>` (or use `passkey_wrap_server` once entries exist in the keychain)."
    )


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
