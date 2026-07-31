"""Passkey MCP Server - Expose passkey tools to AI coding assistants.

This MCP server allows LLMs to discover and use passkey entries.
Importantly, secret VALUES are never exposed through the MCP protocol -
LLMs can only inject secrets via 'passkey run', never read them.
"""

import re as _re
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .keychain import PasskeyError, get_entry, list_entries
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

# Initialize MCP server
mcp = FastMCP(name="passkey")


@mcp.tool()
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


@mcp.tool()
def passkey_fields(entry_name: str) -> list[str]:
    """List field names in a passkey entry (without revealing values).

    Returns the names of secret fields stored in the specified entry.
    This allows discovering what secrets are available without exposing
    the actual secret values.

    Args:
        entry_name: Name of the passkey entry (e.g., "slack")

    Returns:
        List of field names (e.g., ["SLACK_TOKEN", "SLACK_COOKIE"])

    Raises:
        Exception: If entry not found or keychain access fails
    """
    try:
        entry = get_entry(entry_name)
        if entry is None:
            raise Exception(f"Entry '{_sanitize(entry_name)}' not found")
        return list(entry.fields.keys())
    except PasskeyError as e:
        raise Exception(f"Failed to access keychain: {e}") from e


@mcp.tool()
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


@mcp.tool()
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
    _FORBIDDEN_PREFIXES = (
        "/etc/", "/dev/", "/proc/", "/sys/", "/bin/", "/sbin/",
        "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/lib/", "/boot/",
        "/var/root/", "/System/",
    )
    resolved = []
    for p in paths:
        pp = Path(p).expanduser().resolve()
        if pp.suffix not in (".json", ".jsonc"):
            continue
        if str(pp).startswith(_FORBIDDEN_PREFIXES):
            continue
        resolved.append(pp)
    return resolved


_SAFE_NAME = _re.compile(r"[^a-zA-Z0-9._\-\s]")


def _sanitize(s: str) -> str:
    """Strip characters unsafe for log/error output."""
    return _SAFE_NAME.sub("", s)


@mcp.tool()
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


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
