"""MCP configuration command handlers for passkey.

Tool-agnostic commands that work across Claude, Gemini, VS Code,
Cursor, OpenCode, Windsurf, Cline, and Zed.
"""

import contextlib
import json
import sys
from pathlib import Path

from .audit import log_operation
from .interactive import format_secret_preview, parse_field_shorthand, prompt_secret
from .keychain import PasskeyError, get_all_entry_metas, get_entry, list_entries, save_entry
from .mcp_config import (
    ADAPTERS,
    MCPConfigError,
    ToolAdapter,
    backup_config,
    extract_secrets,
    get_backups_dir,
    get_env_from_server,
    get_mcp_servers,
    get_server_security_status,
    get_wrapped_entry_name,
    is_file_exposed_in_git,
    is_passkey_wrapped,
    load_config,
    rewrite_server_for_passkey,
    save_config,
    set_mcp_servers,
)
from .models import Entry


def detect_exposed_mcp_servers() -> list[dict]:
    """Scan all supported MCP tool configs for servers with plaintext secrets.

    Read-only and resilient to malformed config files so FTUE never crashes.
    """
    exposed: list[dict] = []
    for adapter in ADAPTERS.values():
        for config_path in adapter.get_all_existing_paths():
            try:
                config = load_config(config_path)
            except (FileNotFoundError, MCPConfigError, OSError):
                continue
            servers = get_mcp_servers(config, adapter)
            for server_name, server_config in servers.items():
                if is_passkey_wrapped(server_config):
                    continue
                env = get_env_from_server(server_config, adapter)
                if not env:
                    continue
                secrets, non_secrets = extract_secrets(env)
                if secrets:
                    exposed.append(
                        {
                            "tool": adapter.name,
                            "display_name": adapter.display_name,
                            "config_path": config_path,
                            "server": server_name,
                            "secret_keys": list(secrets.keys()),
                            "non_secret_keys": list(non_secrets.keys()),
                        }
                    )
    return exposed


def _resolve_adapter(tool: str | None = None, *, prefer_exposed: bool = False) -> ToolAdapter:
    """Resolve a tool name to its adapter.

    Args:
        tool: Tool name (e.g., "claude", "vscode"). If None, prompts user.
        prefer_exposed: When True and multiple configs exist, auto-select if
            only one tool actually contains exposed secrets.

    Returns:
        The matching ToolAdapter

    Raises:
        PasskeyError: If tool name is invalid or no configs found
    """
    if tool and tool in ADAPTERS:
        return ADAPTERS[tool]

    if tool and tool not in ADAPTERS:
        raise PasskeyError(
            f"Unknown tool '{tool}'. Supported tools: {', '.join(sorted(ADAPTERS.keys()))}"
        )

    from .mcp_config import get_all_config_paths

    existing = get_all_config_paths()

    if not existing:
        raise PasskeyError("No MCP config files found.")

    unique_tools: list[tuple[str, ToolAdapter, Path]] = []
    seen: set[str] = set()
    for tool_name, path in existing:
        if tool_name not in seen:
            seen.add(tool_name)
            unique_tools.append((tool_name, ADAPTERS[tool_name], path))

    if len(unique_tools) == 1:
        return unique_tools[0][1]

    if prefer_exposed:
        exposed_tools = {item["tool"] for item in detect_exposed_mcp_servers()}
        matching = [t for t in unique_tools if t[0] in exposed_tools]
        if len(matching) == 1:
            return matching[0][1]
        if len(matching) > 1:
            unique_tools = matching

    from .interactive import InteractiveRequiredError, can_prompt_interactively

    if not can_prompt_interactively():
        tool_list = ", ".join(t[0] for t in unique_tools)
        raise InteractiveRequiredError(
            f"Multiple MCP configs detected ({tool_list}) in non-interactive mode.\n"
            f"  Re-run with an explicit tool flag, e.g.: passkey init --tool {unique_tools[0][0]}"
        )

    print("Multiple MCP configs detected:\n")
    for idx, (_, adapter, path) in enumerate(unique_tools, 1):
        print(f"  {idx}. {adapter.display_name} ({path})")

    print()
    try:
        choice = input("Select tool [1]: ").strip() or "1"
        idx = int(choice) - 1
        if 0 <= idx < len(unique_tools):
            return unique_tools[idx][1]
    except (ValueError, IndexError, KeyboardInterrupt, EOFError):
        pass

    raise PasskeyError("Invalid selection.")


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
    *,
    yes: bool = False,
) -> None:
    """Migrate MCP config secrets to system keychain.

    Scans the selected tool's MCP config for plaintext secrets,
    stores them in the keychain, and rewrites the config to use
    the passkey wrapper.
    """
    if config_path and not tool:
        from .mcp_config import find_adapter_for_path

        inferred = find_adapter_for_path(Path(config_path).expanduser())
        adapter = inferred if inferred is not None else _resolve_adapter(tool, prefer_exposed=True)
    else:
        adapter = _resolve_adapter(tool, prefer_exposed=(tool is None and config_path is None))

    if config_path:
        path = Path(config_path)
    else:
        global_path = adapter.get_global_path()
        existing_paths = adapter.get_all_existing_paths()
        if global_path and (global_path.exists() or not existing_paths):
            path = global_path
        elif existing_paths:
            path = existing_paths[0]
        else:
            raise PasskeyError(
                f"No config path for {adapter.display_name} on this platform."
            )

    try:
        config = load_config(path)
    except FileNotFoundError as e:
        raise PasskeyError(str(e)) from e
    except MCPConfigError as e:
        raise PasskeyError(str(e)) from e

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

    backup_preview = (
        backup_path
        if backup_path
        else f"{get_backups_dir()}/{path.name}.<timestamp>.backup"
    )
    rollback_cmd = f"passkey unwrap --tool {adapter.name}"
    if config_path and Path(config_path) != adapter.get_global_path():
        rollback_cmd += f" --config {path}"

    # Display crisp per-server migration preview before touching any files
    header = f"Passkey MCP Migration — {adapter.display_name}"
    print(header)
    print("─" * len(header))
    print(f"  Config:   {path}")
    print(f"  Backup:   {backup_preview} (0o600)")
    print(f"  Rollback: {rollback_cmd}")
    print()
    print(f"Preview ({len(to_migrate)} server(s)):")
    print()

    for name, info in to_migrate.items():
        secrets = info["secrets"]
        non_secrets = info["non_secrets"]
        print(f"  {name}  →  OS keychain entry '{name}'")
        print("    Move to keychain (masked):")
        key_w = max(len(k) for k in secrets)
        for key, val in secrets.items():
            print(f"      • {key:<{key_w}}  {format_secret_preview(val)}")
        if non_secrets:
            print("    Keep inline (non-secret):")
            for key, val in non_secrets.items():
                print(f"      • {key} = {val}")
        else:
            print("    Keep inline (non-secret): (none)")
        print()

    if dry_run:
        print("[Dry run — no config files or keychain entries were modified]")
        return

    if not yes:
        confirm = input("Apply migration now? [Y/n]: ").strip().lower()
        if confirm not in ("", "y", "yes"):
            print("Cancelled.")
            return

    print()

    # Create backup
    try:
        backup_target = Path(backup_path) if backup_path else None
        actual_backup = backup_config(path, backup_target)
        print(f"Backup saved (0o600): {actual_backup}")
        if backup_target and is_file_exposed_in_git(actual_backup):
            print(
                f"WARNING: Custom backup '{actual_backup}' is inside a git worktree and not gitignored!",
                file=sys.stderr,
            )
    except Exception as e:
        raise PasskeyError(f"Error creating backup: {e}") from e

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
            save_entry(entry, is_update=(name in existing_entries))

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
        raise PasskeyError(f"Error saving config: {e}") from e

    print()
    print(f"Done! {created} created, {updated} updated, {skipped} skipped")
    print()
    print("SECURITY NOTE: The backup file contains your pre-migration config.")
    print(f"  Once verified, you can delete it: rm '{actual_backup}'")
    print()
    print(f"Restart {adapter.display_name} to apply changes.")
    print(f"Verify status:  passkey status --tool {adapter.name}")
    print(f"Undo anytime:   {rollback_cmd}")

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
            raise PasskeyError(
                f"Unknown tool '{tool}'. Supported tools: {', '.join(sorted(ADAPTERS.keys()))}"
            )
        adapters_to_check = [ADAPTERS[tool]]
    else:
        # Check all tools that have configs
        for adapter in ADAPTERS.values():
            if adapter.get_all_existing_paths():
                adapters_to_check.append(adapter)

    if not adapters_to_check:
        if json_output:
            print("[]")
        else:
            print("No MCP config files found.")
        return

    try:
        metas = get_all_entry_metas(hydrate_unmigrated=False)
    except PasskeyError as e:
        raise PasskeyError(str(e)) from e

    passkey_entries = [m.name for m in metas]
    entry_field_counts = {m.name: len(m.fields) for m in metas if m.hydrated}

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


def cmd_doctor(deep: bool = False, *, json_output: bool = False) -> int:
    """Run diagnostics across all detected MCP tool configs.

    Thin CLI printer over doctor.run_diagnostics — the single
    implementation shared with the passkey_doctor MCP tool.
    """
    from .doctor import run_diagnostics

    result = run_diagnostics(deep=deep)
    checks = result["checks"]
    issues = result["issues"]
    recommendations = result["recommendations"]

    if json_output:
        print(json.dumps(result, indent=2))
        return 1 if result["summary"]["failed"] > 0 else 0

    print("Passkey Doctor" + (" (deep)" if deep else ""))
    print("=" * 35)
    print()

    symbols = {"pass": "\u2713", "warn": "\u26a0", "fail": "\u2717"}
    for check in checks:
        symbol = symbols.get(check["status"], "?")
        print(f"  [{symbol}] {check['message']}")

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
    return 0


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
            raise PasskeyError(
                f"Unknown tool '{tool}'. Supported tools: {', '.join(sorted(ADAPTERS.keys()))}"
            )
        adapters_to_check = [ADAPTERS[tool]]
    else:
        for adapter in ADAPTERS.values():
            if adapter.get_all_existing_paths():
                adapters_to_check.append(adapter)

    if not adapters_to_check:
        if json_output:
            print("[]")
        else:
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
                    entry_name = get_wrapped_entry_name(server_config) or name
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
# unwrap — restore passkey-wrapped configs to inline commands
# ---------------------------------------------------------------------------


def cmd_unwrap(
    tool: str | None = None,
    server: str | None = None,
    config_path: str | None = None,
    restore_secrets: bool = False,
    dry_run: bool = False,
) -> None:
    """Restore passkey-wrapped MCP server configs back to inline commands.

    This is the way out of the one-way door: it reverses what
    ``passkey init`` (and passkey_wrap_server) did. By default only the
    command structure is restored — secret values stay in the keychain and
    are NOT written back unless --restore-secrets is given.
    """
    from .mcp_config import restore_server_from_passkey

    # Resolve which (adapter, path) pairs to operate on
    targets: list[tuple[ToolAdapter, Path]] = []
    if config_path:
        path = Path(config_path).expanduser()
        adapter = None
        if tool:
            if tool not in ADAPTERS:
                raise PasskeyError(
                    f"Unknown tool '{tool}'. Supported tools: {', '.join(sorted(ADAPTERS.keys()))}"
                )
            adapter = ADAPTERS[tool]
        else:
            from .mcp_config import find_adapter_for_path

            adapter = find_adapter_for_path(path)
            if not adapter:
                raise PasskeyError(
                    f"'{path}' is not a known MCP config location. "
                    "Use --tool to specify the tool (e.g. --tool claude)."
                )
        targets.append((adapter, path))
    elif tool:
        if tool not in ADAPTERS:
            raise PasskeyError(
                f"Unknown tool '{tool}'. Supported tools: {', '.join(sorted(ADAPTERS.keys()))}"
            )
        adapter = ADAPTERS[tool]
        for path in adapter.get_all_existing_paths():
            targets.append((adapter, path))
        if not targets:
            print(f"No config files found for {adapter.display_name}.")
            return
    else:
        for adapter in ADAPTERS.values():
            for path in adapter.get_all_existing_paths():
                targets.append((adapter, path))
        if not targets:
            print("No MCP config files found.")
            return

    if restore_secrets:
        print("WARNING: --restore-secrets writes secret values back into")
        print("plaintext config files. This reverses passkey's protection.")
        print()

    unwrapped_total = 0

    for adapter, path in targets:
        try:
            config = load_config(path)
        except (FileNotFoundError, MCPConfigError) as e:
            print(f"Error loading {path}: {e}", file=sys.stderr)
            continue

        servers = get_mcp_servers(config, adapter)
        to_restore = {}
        for name, server_config in servers.items():
            if server and name != server:
                continue
            if is_passkey_wrapped(server_config):
                to_restore[name] = server_config

        if not to_restore:
            if server:
                print(f"{adapter.display_name}: server '{server}' is not passkey-wrapped here.")
            continue

        print(f"{adapter.display_name} — {path}")

        secrets_by_name: dict[str, dict] = {}
        if restore_secrets:
            for name in to_restore:
                entry = get_entry(name)
                if entry:
                    secrets_by_name[name] = dict(entry.fields)
                else:
                    print(
                        f"  Warning: no passkey entry '{name}' found; "
                        "secrets cannot be restored for it.",
                        file=sys.stderr,
                    )

        for name, server_config in to_restore.items():
            restored = restore_server_from_passkey(
                server_config, adapter, secrets=secrets_by_name.get(name)
            )
            secret_note = ""
            if restore_secrets:
                count = len(secrets_by_name.get(name, {}))
                secret_note = f" (+{count} secret(s) restored to config)"
            print(f"  {name}: unwrapped{secret_note}")
            servers[name] = restored

        if dry_run:
            print("  [dry run — config not written]")
            print()
            unwrapped_total += len(to_restore)
            continue

        try:
            backup = backup_config(path)
            set_mcp_servers(config, adapter, servers)
            save_config(config, path)
            print(f"  Backup: {backup}")
            print()
            unwrapped_total += len(to_restore)
        except Exception as e:
            print(f"  Error saving config: {e}", file=sys.stderr)

    if unwrapped_total and not dry_run:
        print(f"Unwrapped {unwrapped_total} server(s).")
        print("Passkey entries were left in the keychain.")
        print("Delete them with 'passkey delete <name>' if no longer needed.")
        log_operation("unwrap", details={"count": unwrapped_total})
    elif unwrapped_total:
        print(f"[dry run] {unwrapped_total} server(s) would be unwrapped.")
    else:
        print("Nothing to unwrap.")


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
        raise PasskeyError(str(e)) from e

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
            value = prompt_secret(f"  Value for {field_name}")
            new_fields[field_name] = value
            print(f"  + {field_name}  {format_secret_preview(value)}")
    else:
        print("Enter fields (paste KEY=VALUE or enter field name; leave blank to finish):")
        print()
        while True:
            try:
                raw_field = input("  Field name: ").strip()
            except EOFError:
                break
            if not raw_field:
                break
            field_name, inline_val = parse_field_shorthand(raw_field)
            if not field_name:
                print("  Field name cannot be empty.")
                continue
            value = (
                inline_val
                if inline_val is not None
                else prompt_secret(f"  Value for {field_name}")
            )
            new_fields[field_name] = value
            print(f"  + {field_name}  {format_secret_preview(value)}")
            print()

    if not new_fields:
        print("No fields entered. Cancelled.")
        return

    # Merge with existing
    final_fields = {}
    if existing_entry:
        final_fields = existing_entry.fields.copy()
    final_fields.update(new_fields)

    # Save entry (preserve existing metadata per Landmine #3)
    try:
        if existing_entry:
            entry = Entry(
                name=server,
                fields=final_fields,
                config=existing_entry.config,
                created=existing_entry.created,
                source=existing_entry.source or f"{adapter.name}-add",
                last_rotated=existing_entry.last_rotated,
                policy=existing_entry.policy,
            )
            save_entry(entry, is_update=True)
        else:
            entry = Entry(name=server, fields=final_fields, source=f"{adapter.name}-add")
            save_entry(entry)
        print(f"Saved {len(new_fields)} new field(s) to passkey entry '{server}'")
    except PasskeyError as e:
        raise PasskeyError(str(e)) from e

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
