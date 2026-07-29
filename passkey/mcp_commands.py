"""MCP configuration command handlers for passkey.

Tool-agnostic commands that work across Claude, Gemini, VS Code,
Cursor, OpenCode, Windsurf, Cline, and Zed.
"""

import contextlib
import getpass
import json
import sys
from pathlib import Path

from .audit import log_operation
from .keychain import PasskeyError, get_entry, list_entries, save_entry
from .mcp_config import (
    ADAPTERS,
    MCPConfigError,
    ToolAdapter,
    backup_config,
    extract_secrets,
    find_passkey_command,
    get_env_from_server,
    get_mcp_servers,
    get_server_security_status,
    is_passkey_wrapped,
    load_config,
    rewrite_server_for_passkey,
    save_config,
    set_mcp_servers,
)
from .models import Entry


def _resolve_adapter(tool: str | None = None) -> ToolAdapter:
    """Resolve a tool name to its adapter.

    Args:
        tool: Tool name (e.g., "claude", "vscode"). If None, prompts user.

    Returns:
        The matching ToolAdapter

    Raises:
        SystemExit: If tool name is invalid
    """
    if tool and tool in ADAPTERS:
        return ADAPTERS[tool]

    if tool and tool not in ADAPTERS:
        print(f"Error: Unknown tool '{tool}'", file=sys.stderr)
        print(f"Supported tools: {', '.join(sorted(ADAPTERS.keys()))}", file=sys.stderr)
        sys.exit(1)

    # No tool specified — find existing configs and prompt
    from .mcp_config import get_all_config_paths

    existing = get_all_config_paths()

    if not existing:
        print("No MCP config files found.", file=sys.stderr)
        sys.exit(1)

    if len(existing) == 1:
        tool_name, _ = existing[0]
        return ADAPTERS[tool_name]

    # Multiple tools found — show selection
    print("Multiple MCP configs detected:\n")
    seen = set()
    choices = []
    for tool_name, path in existing:
        if tool_name not in seen:
            seen.add(tool_name)
            adapter = ADAPTERS[tool_name]
            choices.append((tool_name, adapter, path))
            print(f"  {len(choices)}. {adapter.display_name} ({path})")

    print()
    try:
        choice = input("Select tool [1]: ").strip() or "1"
        idx = int(choice) - 1
        if 0 <= idx < len(choices):
            return choices[idx][1]
    except (ValueError, IndexError):
        pass

    print("Invalid selection.", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# init — migrate MCP config secrets to keychain
# ---------------------------------------------------------------------------


def cmd_init(
    tool: str | None = None,
    config_path: str | None = None,
    dry_run: bool = False,
    force: bool = False,
    include_all: bool = False,
    backup_path: str | None = None,
) -> None:
    """Migrate MCP config secrets to system keychain.

    Scans the selected tool's MCP config for plaintext secrets,
    stores them in the keychain, and rewrites the config to use
    the passkey wrapper.
    """
    adapter = _resolve_adapter(tool)

    if config_path:
        path = Path(config_path)
    else:
        path = adapter.get_global_path()
        if not path:
            print(
                f"Error: No config path for {adapter.display_name} on this platform.",
                file=sys.stderr,
            )
            sys.exit(1)

    try:
        config = load_config(path)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except MCPConfigError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    servers = get_mcp_servers(config, adapter)
    if not servers:
        print(f"No MCP servers found in {adapter.display_name} config.")
        return

    # Find servers with secrets
    to_migrate = {}
    for name, server_config in servers.items():
        if is_passkey_wrapped(server_config) and not force:
            continue

        env = get_env_from_server(server_config, adapter)
        if not env:
            continue

        if include_all:
            secrets = env
            non_secrets = {}
        else:
            secrets, non_secrets = extract_secrets(env)

        if secrets:
            to_migrate[name] = {
                "secrets": secrets,
                "non_secrets": non_secrets,
                "config": server_config,
            }

    if not to_migrate:
        print("No secrets found to migrate.")
        print("All servers either have no env vars or are already using passkey.")
        return

    # Display summary
    print(f"Passkey Integration — {adapter.display_name}")
    print("=" * (25 + len(adapter.display_name)))
    print()
    print(f"Config: {path}")
    print(f"Found {len(to_migrate)} server(s) with credentials:")
    print()

    for name, info in to_migrate.items():
        secret_count = len(info["secrets"])
        print(f"  {name}: {secret_count} secret(s) detected")
        for key in info["secrets"]:
            print(f"    - {key}")

    print()

    if dry_run:
        print("[Dry run - no changes will be made]")
        print()
        print("This would:")
        print("  1. Store secrets in system keychain")
        print("  2. Update config to use passkey wrapper")
        print(f"  3. Create backup at {path}{backup_path if backup_path else '.backup'}")
        return

    # Confirm
    print("This will:")
    print("  1. Store secrets in system keychain")
    print("  2. Update config to use passkey wrapper")
    print(f"  3. Create backup at {path}.backup")
    print()

    confirm = input("Continue? [Y/n]: ").strip().lower()
    if confirm not in ("", "y", "yes"):
        print("Cancelled.")
        return

    print()

    # Create backup
    try:
        backup_target = Path(backup_path) if backup_path else None
        actual_backup = backup_config(path, backup_target)
        print(f"Backup created: {actual_backup}")
    except Exception as e:
        print(f"Error creating backup: {e}", file=sys.stderr)
        sys.exit(1)

    # Migrate each server
    print()
    print("Migrating servers...")

    existing_entries = list_entries()
    created = 0
    updated = 0
    skipped = 0

    for name, info in to_migrate.items():
        secrets = info["secrets"]

        if name in existing_entries and not force:
            print(f"  {name}: skipped (entry exists, use --force to overwrite)")
            skipped += 1
            continue

        try:
            entry = Entry(name=name, fields=secrets, source=f"{adapter.name}-init")
            save_entry(entry)

            if name in existing_entries:
                print(f"  {name}: updated ({len(secrets)} secrets)")
                updated += 1
            else:
                print(f"  {name}: created ({len(secrets)} secrets)")
                created += 1

            new_server = rewrite_server_for_passkey(name, info["config"], adapter)
            servers[name] = new_server

        except PasskeyError as e:
            print(f"  {name}: error - {e}", file=sys.stderr)
            skipped += 1

    # Save updated config
    try:
        set_mcp_servers(config, adapter, servers)
        save_config(config, path)
    except Exception as e:
        print(f"Error saving config: {e}", file=sys.stderr)
        sys.exit(1)

    print()
    print(f"Done! {created} created, {updated} updated, {skipped} skipped")
    print()
    print("SECURITY NOTE: The backup file may contain plaintext secrets.")
    print(f"  Consider deleting: rm '{actual_backup}'")
    print()
    print(f"Restart {adapter.display_name} to apply changes.")
    print(f"Run 'passkey status --tool {adapter.name}' to verify.")

    log_operation(
        f"{adapter.name}-init",
        details={
            "created": created,
            "updated": updated,
            "skipped": skipped,
        },
    )


# ---------------------------------------------------------------------------
# status — show security status
# ---------------------------------------------------------------------------


def cmd_status(
    tool: str | None = None,
    json_output: bool = False,
) -> None:
    """Show MCP server security status across tools.

    If no tool is specified, scans all detected configs.
    """
    adapters_to_check = []

    if tool:
        if tool not in ADAPTERS:
            print(f"Error: Unknown tool '{tool}'", file=sys.stderr)
            sys.exit(1)
        adapters_to_check = [ADAPTERS[tool]]
    else:
        # Check all tools that have configs
        for adapter in ADAPTERS.values():
            if adapter.get_all_existing_paths():
                adapters_to_check.append(adapter)

    if not adapters_to_check:
        print("No MCP config files found.")
        return

    try:
        passkey_entries = list_entries()
    except PasskeyError as e:
        print(f"Error accessing keychain: {e}", file=sys.stderr)
        sys.exit(1)

    # Get entry field counts
    entry_field_counts = {}
    for entry_name in passkey_entries:
        try:
            entry = get_entry(entry_name)
            if entry:
                entry_field_counts[entry_name] = len(entry.fields)
        except PasskeyError:
            pass

    all_results = []

    for adapter in adapters_to_check:
        for config_path in adapter.get_all_existing_paths():
            try:
                config = load_config(config_path)
            except (FileNotFoundError, MCPConfigError) as e:
                print(f"Error loading {config_path}: {e}", file=sys.stderr)
                continue

            servers = get_mcp_servers(config, adapter)
            if not servers:
                continue

            tool_results = []
            for name, server_config in servers.items():
                status = get_server_security_status(name, server_config, passkey_entries, adapter)
                if status["passkey_entry"] and status["passkey_entry"] in entry_field_counts:
                    status["field_count"] = entry_field_counts[status["passkey_entry"]]
                status["tool"] = adapter.name
                status["config_path"] = str(config_path)
                tool_results.append(status)

            all_results.extend(tool_results)

            if not json_output:
                secured = sum(1 for r in tool_results if r["status"] == "secured")
                partial = sum(1 for r in tool_results if r["status"] == "partial")
                exposed = sum(1 for r in tool_results if r["status"] == "exposed")
                len(tool_results)

                print(f"\n{adapter.display_name} — {config_path}")
                print("-" * 50)

                status_symbols = {
                    "secured": "\u2713 Secured",
                    "partial": "\u26a0 Partial",
                    "exposed": "\u2717 Exposed",
                    "broken": "\u2717 Broken",
                    "no_secrets": "- No secrets",
                    "unknown": "? Unknown",
                }

                for result in tool_results:
                    symbol = status_symbols.get(result["status"], "?")
                    entry_info = ""
                    if result["passkey_entry"]:
                        field_count = result.get("field_count", "?")
                        entry_info = f"{result['passkey_entry']} ({field_count} fields)"
                    else:
                        entry_info = "-"

                    env_info = ""
                    if result["exposed_secrets"]:
                        env_info = ", ".join(result["exposed_secrets"][:2])
                        if len(result["exposed_secrets"]) > 2:
                            env_info += f" +{len(result['exposed_secrets']) - 2}"
                        env_info += " (!)"
                    elif result["non_secret_env"]:
                        env_info = ", ".join(result["non_secret_env"][:2])
                        if len(result["non_secret_env"]) > 2:
                            env_info += f" +{len(result['non_secret_env']) - 2}"

                    print(f"  {result['server']:15} {symbol:12} {entry_info:20} {env_info}")

                print(f"\n  Summary: {secured} secured, {partial} partial, {exposed} exposed")

    if json_output:
        print(json.dumps(all_results, indent=2))
        return

    total_secured = sum(1 for r in all_results if r["status"] == "secured")
    total_partial = sum(1 for r in all_results if r["status"] == "partial")
    total_exposed = sum(1 for r in all_results if r["status"] == "exposed")

    if len(adapters_to_check) > 1:
        print(f"\n{'=' * 50}")
        print(f"Total: {total_secured} secured, {total_partial} partial, {total_exposed} exposed")

    if total_exposed > 0:
        print()
        print("Run 'passkey init' to secure exposed servers.")


# ---------------------------------------------------------------------------
# doctor — run diagnostics
# ---------------------------------------------------------------------------


def cmd_doctor() -> None:
    """Run diagnostics across all detected MCP tool configs."""
    print("Passkey Doctor")
    print("=" * 35)
    print()

    checks = []
    issues = []
    recommendations = []

    # Check 1: Passkey in PATH
    passkey_path = find_passkey_command()
    if passkey_path:
        checks.append(("passkey_in_path", "pass", f"Passkey found at {passkey_path}"))
    else:
        checks.append(("passkey_in_path", "fail", "Passkey not found in PATH"))
        issues.append("Passkey command not in PATH")
        recommendations.append("Install passkey: pip install passkey-mcp")

    # Check 2: Keychain access
    try:
        entries = list_entries()
        checks.append(("keychain_access", "pass", f"Keychain accessible ({len(entries)} entries)"))
    except PasskeyError as e:
        checks.append(("keychain_access", "fail", f"Keychain access failed: {e}"))
        issues.append("Cannot access system keychain")
        recommendations.append("Check system keychain access permissions")

    # Check 3: Each tool's config
    for adapter in ADAPTERS.values():
        config_paths = adapter.get_all_existing_paths()
        if not config_paths:
            continue

        for config_path in config_paths:
            try:
                config = load_config(config_path)
                servers = get_mcp_servers(config, adapter)
                checks.append(
                    (
                        f"{adapter.name}_config",
                        "pass",
                        f"{adapter.display_name} config found ({len(servers)} servers)",
                    )
                )

                for name, server_config in servers.items():
                    status = get_server_security_status(name, server_config, entries, adapter)
                    if status["status"] == "broken":
                        issues.append(
                            f"Missing passkey entry for server '{name}' in {adapter.display_name}"
                        )
                        recommendations.append(
                            f"Run 'passkey init --tool {adapter.name}' to secure"
                        )
                    elif status["status"] == "exposed":
                        issues.append(
                            f"Server '{name}' has exposed secrets in {adapter.display_name}: "
                            f"{', '.join(status['exposed_secrets'])}"
                        )
                        recommendations.append(
                            f"Run 'passkey init --tool {adapter.name}' to secure"
                        )

            except MCPConfigError as e:
                checks.append(
                    (
                        f"{adapter.name}_config",
                        "fail",
                        f"{adapter.display_name} config invalid: {e}",
                    )
                )
                issues.append(f"{adapter.display_name} config is invalid")

    # Print results
    for _name, status, message in checks:
        symbol = "\u2713" if status == "pass" else "\u2717"
        print(f"  [{symbol}] {message}")

    if issues:
        print()
        print(f"Issues found: {len(issues)}")
        for i, issue in enumerate(issues, 1):
            print(f"  {i}. {issue}")
        print()
        print("Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    else:
        print()
        print("All checks passed!")

    log_operation("doctor", details={"checks": len(checks), "issues": len(issues)})


# ---------------------------------------------------------------------------
# servers — list servers
# ---------------------------------------------------------------------------


def cmd_servers(
    tool: str | None = None,
    json_output: bool = False,
) -> None:
    """List MCP servers across detected tools."""
    adapters_to_check = []

    if tool:
        if tool not in ADAPTERS:
            print(f"Error: Unknown tool '{tool}'", file=sys.stderr)
            sys.exit(1)
        adapters_to_check = [ADAPTERS[tool]]
    else:
        for adapter in ADAPTERS.values():
            if adapter.get_all_existing_paths():
                adapters_to_check.append(adapter)

    if not adapters_to_check:
        print("No MCP config files found.")
        return

    with contextlib.suppress(PasskeyError):
        list_entries()

    all_results = []

    for adapter in adapters_to_check:
        for config_path in adapter.get_all_existing_paths():
            try:
                config = load_config(config_path)
            except (FileNotFoundError, MCPConfigError) as e:
                print(f"Error loading {config_path}: {e}", file=sys.stderr)
                continue

            servers = get_mcp_servers(config, adapter)
            if not servers:
                continue

            for name, server_config in servers.items():
                if is_passkey_wrapped(server_config):
                    args = server_config.get("args", [])
                    entry_name = args[1] if len(args) >= 2 and args[0] == "run" else name
                    result = {
                        "name": name,
                        "tool": adapter.name,
                        "mode": "passkey",
                        "entry": entry_name,
                        "config_path": str(config_path),
                    }
                else:
                    env = get_env_from_server(server_config, adapter)
                    secrets, _ = extract_secrets(env)
                    result = {
                        "name": name,
                        "tool": adapter.name,
                        "mode": "plaintext" if secrets else "no_secrets",
                        "exposed_count": len(secrets),
                        "config_path": str(config_path),
                    }
                all_results.append(result)

    if json_output:
        print(json.dumps(all_results, indent=2))
        return

    for adapter in adapters_to_check:
        tool_results = [r for r in all_results if r["tool"] == adapter.name]
        if not tool_results:
            continue

        print(f"\n{adapter.display_name}:")
        secured_count = 0
        for result in tool_results:
            if result["mode"] == "passkey":
                print(f"  {result['name']:15} \u2192 passkey-secured ({result['entry']})")
                secured_count += 1
            elif result["mode"] == "plaintext":
                print(f"  {result['name']:15} \u2192 plaintext ({result['exposed_count']} secrets)")
            else:
                print(f"  {result['name']:15} \u2192 no secrets")

        print(f"  {len(tool_results)} servers ({secured_count} secured)")

    if not all_results:
        print("No MCP servers found.")


# ---------------------------------------------------------------------------
# add — add credentials for a server
# ---------------------------------------------------------------------------


def cmd_add(
    server: str,
    tool: str | None = None,
    fields: list[str] | None = None,
) -> None:
    """Add or update credentials for an MCP server."""
    adapter = _resolve_adapter(tool)

    # Load config to check if server exists
    config = None
    server_config = None
    config_path = adapter.get_global_path()

    if config_path and config_path.exists():
        try:
            config = load_config(config_path)
            servers = get_mcp_servers(config, adapter)
            if server in servers:
                server_config = servers[server]
        except (FileNotFoundError, MCPConfigError):
            pass

    # Check for existing passkey entry
    existing_entry = None
    try:
        existing_entry = get_entry(server)
    except PasskeyError as e:
        print(f"Error accessing keychain: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Adding credentials for: {server}")
    if adapter:
        print(f"Tool: {adapter.display_name}")
    print()

    if existing_entry:
        print(f"Existing passkey entry has {len(existing_entry.fields)} field(s):")
        for key in existing_entry.fields:
            print(f"  - {key}")
        print()

    if server_config and not is_passkey_wrapped(server_config):
        env = get_env_from_server(server_config, adapter)
        secrets, _ = extract_secrets(env)
        if secrets:
            print("Current config shows these secrets in plaintext:")
            for key in secrets:
                print(f"  - {key} (!)")
            print()

    # Collect fields
    new_fields = {}

    if fields:
        for field_name in fields:
            value = getpass.getpass(f"  Value for {field_name}: ")
            new_fields[field_name] = value
    else:
        print("Enter fields (leave name blank to finish):")
        print()
        while True:
            field_name = input("  Field name: ").strip()
            if not field_name:
                break
            value = getpass.getpass(f"  Value for {field_name}: ")
            new_fields[field_name] = value
            print()

    if not new_fields:
        print("No fields entered. Cancelled.")
        return

    # Merge with existing
    final_fields = {}
    if existing_entry:
        final_fields = existing_entry.fields.copy()
    final_fields.update(new_fields)

    # Save entry
    try:
        entry = Entry(name=server, fields=final_fields, source=f"{adapter.name}-add")
        save_entry(entry)
        print(f"Saved {len(new_fields)} new field(s) to passkey entry '{server}'")
    except PasskeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Update config if server exists and not already using passkey
    if server_config and not is_passkey_wrapped(server_config) and config and config_path:
        new_server = rewrite_server_for_passkey(server, server_config, adapter)
        servers = get_mcp_servers(config, adapter)
        servers[server] = new_server
        set_mcp_servers(config, adapter, servers)

        try:
            backup_config(config_path)
            save_config(config, config_path)
            print(f"Updated {adapter.display_name} config to use passkey wrapper")
        except Exception as e:
            print(f"Warning: Could not update config: {e}", file=sys.stderr)

    elif not server_config:
        print()
        print(f"Server not found in {adapter.display_name} config. To use, add:")
        print()
        if adapter.command_is_array:
            print(f'  "{server}": {{')
            print(f'    "command": ["passkey", "run", "{server}", "--", "your-command", "here"]')
            print("  }")
        else:
            print(f'  "{server}": {{')
            print('    "command": "passkey",')
            print(f'    "args": ["run", "{server}", "--", "your-command", "here"]')
            print("  }")

    print()
    print(f"Restart {adapter.display_name} to apply changes.")

    log_operation(f"{adapter.name}-add", server, {"field_count": len(new_fields)})


# ---------------------------------------------------------------------------
# Backward-compat aliases for "passkey claude ..." subcommands
# ---------------------------------------------------------------------------


def cmd_claude_init(**kwargs) -> None:
    """Alias for cmd_init with tool='claude'."""
    kwargs.setdefault("tool", "claude")
    cmd_init(**kwargs)


def cmd_claude_status(**kwargs) -> None:
    """Alias for cmd_status with tool='claude'."""
    kwargs.setdefault("tool", "claude")
    cmd_status(**kwargs)
