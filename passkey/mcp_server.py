"""Passkey MCP Server - Expose passkey tools to AI coding assistants.

This MCP server allows LLMs to discover and use passkey entries.
Importantly, secret VALUES are never exposed through the MCP protocol -
LLMs can only inject secrets via 'passkey run', never read them.
"""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from .keychain import PasskeyError, get_entry, list_entries
from .mcp_config import (
    ADAPTERS,
    MCPConfigError,
    find_adapter_for_path,
    find_passkey_command,
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


# Backward-compat alias
passkey_list_entries = passkey_list


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
            raise Exception(f"Entry '{entry_name}' not found")
        return list(entry.fields.keys())
    except PasskeyError as e:
        raise Exception(f"Failed to access keychain: {e}") from e


# Backward-compat alias
passkey_get_entry_fields = passkey_fields


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

    for adapter_name, adapter in ADAPTERS.items():
        for config_path in adapter.get_all_existing_paths():
            try:
                config = load_config(config_path)
            except (FileNotFoundError, MCPConfigError):
                continue

            servers = get_mcp_servers(config, adapter)
            if not servers:
                continue

            try:
                passkey_entries = list_entries()
            except PasskeyError:
                passkey_entries = []

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
def passkey_doctor() -> dict:
    """Run diagnostics on passkey and MCP configurations.

    Checks for common issues including:
    - Config file existence and validity for all detected tools
    - Passkey command availability in PATH
    - Keychain access permissions
    - MCP servers with missing passkey entries
    - MCP servers with exposed secrets

    Returns:
        Dictionary with diagnostic results
    """
    checks = []
    issues = []
    recommendations = []

    # Check 1: Passkey in PATH
    passkey_path = find_passkey_command()
    if passkey_path:
        checks.append(
            {
                "name": "passkey_in_path",
                "status": "pass",
                "message": f"Passkey found at {passkey_path}",
            }
        )
    else:
        checks.append(
            {"name": "passkey_in_path", "status": "fail", "message": "Passkey not found in PATH"}
        )
        issues.append("Passkey command not in PATH")
        recommendations.append("Install passkey: pip install passkey-mcp")

    # Check 2: Keychain access
    try:
        pk_entries = list_entries()
        checks.append(
            {
                "name": "keychain_access",
                "status": "pass",
                "message": f"Keychain accessible ({len(pk_entries)} entries)",
            }
        )
    except PasskeyError as e:
        checks.append(
            {"name": "keychain_access", "status": "fail", "message": f"Keychain access failed: {e}"}
        )
        issues.append("Cannot access system keychain")

    # Check 3: Each tool's config
    for adapter_name, adapter in ADAPTERS.items():
        for config_path in adapter.get_all_existing_paths():
            try:
                config = load_config(config_path)
                servers = get_mcp_servers(config, adapter)
                checks.append(
                    {
                        "name": f"{adapter_name}_config",
                        "status": "pass",
                        "message": f"{adapter.display_name} config found ({len(servers)} servers)",
                    }
                )

                for name, server_config in servers.items():
                    status = get_server_security_status(name, server_config, pk_entries, adapter)
                    if status["status"] == "broken":
                        issues.append(
                            f"Missing passkey entry for server '{name}' in {adapter.display_name}"
                        )
                        recommendations.append(
                            f"Run 'passkey init --tool {adapter_name}' to secure"
                        )
                    elif status["status"] == "exposed":
                        issues.append(
                            f"Server '{name}' has exposed secrets in {adapter.display_name}: "
                            f"{', '.join(status['exposed_secrets'])}"
                        )
                        recommendations.append(
                            f"Run 'passkey init --tool {adapter_name}' to secure"
                        )

            except (FileNotFoundError, MCPConfigError) as e:
                checks.append(
                    {
                        "name": f"{adapter_name}_config",
                        "status": "fail",
                        "message": f"{adapter.display_name} config invalid: {e}",
                    }
                )
                issues.append(f"{adapter.display_name} config is invalid")

    summary = {
        "passed": sum(1 for c in checks if c["status"] == "pass"),
        "failed": sum(1 for c in checks if c["status"] == "fail"),
    }

    return {
        "checks": checks,
        "issues": issues,
        "recommendations": recommendations,
        "summary": summary,
    }


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
            "message": f"Passkey entry '{server_name}' not found. Use passkey new first.",
        }

    if config_paths:
        paths = [Path(p).expanduser() for p in config_paths]
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


# Backward-compat alias
passkey_setup_server = passkey_wrap_server


def main():
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
