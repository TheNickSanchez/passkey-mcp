"""CLI package — main entry point for the passkey command."""

import sys

from .. import commands, importers, mcp_commands
from ..keychain import PasskeyError
from ..mcp_server import main as mcp_main
from .handlers import (
    handle_onboarding_or_help,
    handle_run_command,
    handle_template_command,
    resolve_entry,
)
from .parser import create_parser

__all__ = [
    "create_parser",
    "handle_onboarding_or_help",
    "handle_run_command",
    "handle_template_command",
    "main",
    "resolve_entry",
]


_KNOWN_COMMANDS = frozenset(
    {
        "new",
        "list",
        "get",
        "edit",
        "delete",
        "info",
        "clone",
        "set-field",
        "policy",
        "lease",
        "plugin",
        "browser-fill",
        "run",
        "inject",
        "mount",
        "hook",
        "export",
        "import",
        "check",
        "audit",
        "generate",
        "template",
        "share",
        "receive",
        "rotate",
        "unwrap",
        "config",
        "mcp-serve",
        "init",
        "status",
        "doctor",
        "servers",
        "add",
        "completion",
    }
)


def _require_auth(operation: str) -> None:
    """Enforce optional OS authentication for interactive commands.

    Off by default: the primary protection is the OS keychain's own ACL.
    Users can opt in to an extra sudo/polkit prompt with
    ``passkey config require-auth on``. Never called from headless paths
    (``passkey run``), which cannot answer prompts.
    """
    from ..settings import require_auth_enabled

    if not require_auth_enabled():
        return

    from ..auth import require_auth

    require_auth(operation)


def main() -> None:
    """Main entry point with centralized error handling."""
    from ..dirs import run_migration_if_needed

    run_migration_if_needed()

    if (
        len(sys.argv) >= 2
        and not sys.argv[1].startswith("-")
        and sys.argv[1] not in _KNOWN_COMMANDS
    ):
        entry_name = sys.argv[1]
        try:
            _require_auth("access secrets")
            entry = resolve_entry(entry_name, "Select entry to browse")
            commands.cmd_get_interactive(entry)
        except PasskeyError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled by user.", file=sys.stderr)
            sys.exit(1)
        return

    parser = create_parser()
    try:
        import argcomplete

        argcomplete.autocomplete(parser)
    except ImportError:
        pass

    args = parser.parse_args()

    try:
        if args.command == "new":
            _require_auth("create entries")
            commands.cmd_new()
        elif args.command == "list":
            commands.cmd_list(names_only=getattr(args, "names_only", False))
        elif args.command == "get":
            _require_auth("access secrets")
            entry = resolve_entry(args.entry, "Select entry to browse")
            if args.get_all:
                commands.cmd_get_all(entry)
            else:
                commands.cmd_get_interactive(entry)
        elif args.command == "edit":
            _require_auth("edit entries")
            entry = resolve_entry(args.entry, "Select entry to edit")
            commands.cmd_edit(entry)
        elif args.command == "delete":
            _require_auth("delete entries")
            entry = resolve_entry(args.entry, "Select entry to delete", fuzzy=False)
            commands.cmd_delete(entry.name)
        elif args.command == "info":
            commands.cmd_info(resolve_entry(args.entry, "Select entry to view"))
        elif args.command == "clone":
            _require_auth("clone entries")
            source = resolve_entry(args.source, "Select entry to clone", fuzzy=False)
            commands.cmd_clone(source, args.dest)
        elif args.command == "set-field":
            _require_auth("modify entries")
            entry = resolve_entry(args.entry, "Select entry to update", fuzzy=False)
            commands.cmd_set_field(entry, args.field, None)
        elif args.command == "policy":
            if args.policy_value is not None:
                _require_auth("update entry policy")
            entry = resolve_entry(args.entry, "Select entry for policy", fuzzy=False)
            commands.cmd_policy(entry, args.policy_value)
        elif args.command == "lease":
            from ..leases import grant_lease, list_leases, revoke_lease

            if args.lease_command == "grant":
                rec = grant_lease(
                    args.entry,
                    ttl=args.ttl,
                    max_uses=args.max_uses,
                    require_biometric=True,
                )
                uses_note = (
                    f", max uses: {rec['max_uses']}" if rec.get("max_uses") is not None else ""
                )
                print(
                    f"Granted lease for '{rec['entry']}' (TTL: {rec['ttl_seconds']}s{uses_note}, "
                    f"expires {rec['expires_at_iso']})"
                )
            elif args.lease_command == "list":
                active = list_leases()
                if not active:
                    print("No active leases")
                else:
                    for item in active:
                        rem_uses = (
                            f"{item['remaining_uses']}/{item['max_uses']} uses"
                            if item.get("remaining_uses") is not None
                            else "unlimited uses"
                        )
                        print(
                            f"  {item['entry']:<20} {item['seconds_remaining']:>5}s remaining  ({rem_uses})"
                        )
            elif args.lease_command == "revoke":
                revoked = revoke_lease(args.entry, revoke_all=args.revoke_all)
                print(f"Revoked {revoked} lease(s)")
            else:
                raise PasskeyError("Usage: passkey lease [grant|list|revoke]")
        elif args.command == "plugin":
            from ..plugins import init_plugin, list_plugins, run_plugin

            if args.plugin_command == "list":
                for p in list_plugins():
                    env_list = ", ".join(p["env_vars"])
                    print(f"  {p['cli']:<14} -> {p['entry']:<16} [{p['source']}] ({env_list})")
            elif args.plugin_command == "init":
                _require_auth("configure CLI plugin")
                info = init_plugin(args.cli, entry_name=args.entry, scope=args.scope)
                if info["scope"] == "session":
                    print(info["snippet"])
                else:
                    print(
                        f"Configured plugin '{info['cli']}' -> entry '{info['entry']}' ({info['scope']})"
                    )
                    print(f"  Config: {info['config_path']}")
                    print(f"  Shell wrappers: source '{info['shell_path']}'")
            elif args.plugin_command == "run":
                extra = list(args.args or [])
                if extra and extra[0] == "--":
                    extra = extra[1:]
                sys.exit(
                    run_plugin(
                        args.cli,
                        extra,
                        entry_name=args.entry,
                        no_masking=args.no_masking,
                    )
                )
            else:
                raise PasskeyError("Usage: passkey plugin [list|init|run]")
        elif args.command == "browser-fill":
            from ..browser_broker import cdp_autofill

            res = cdp_autofill(args.entry, args.cdp_url)
            print(
                f"Autofilled {', '.join(res['fields_injected'])} on {res['origin']}"
            )
        elif args.command == "run":
            # Never auth-gated: headless path for MCP servers.
            # Protection comes from the OS keychain's own ACL prompts.
            handle_run_command(parser, args)
        elif args.command == "inject":
            _require_auth("inject secrets into file")
            commands.cmd_inject(
                args.in_file,
                args.out_file,
                to_stdout=args.stdout,
                force=args.force,
            )
        elif args.command == "mount":
            _require_auth("mount ephemeral secret FIFO")
            from ..mount import mount_env_fifo

            max_reads = 1 if args.once else args.max_reads
            mount_env_fifo(
                args.entries,
                path=args.path,
                max_reads=max_reads,
                force_git_exposed=args.force_git_exposed,
                quiet=args.quiet,
            )
        elif args.command == "hook":
            from pathlib import Path as _Path

            from ..hooks import install_hook, run_hook_check

            if args.hook_command == "install":
                proj = _Path(args.project_dir) if args.project_dir else None
                target = install_hook(args.tool, project_dir=proj)
                print(f"Installed passkey guard hook for {args.tool} at {target}")
            elif args.hook_command == "check":
                sys.exit(run_hook_check(tool=args.tool))
            else:
                raise PasskeyError("Usage: passkey hook [install|check]")
        elif args.command == "export":
            _require_auth("export secrets")
            if args.encrypt:
                from ..bundle import export_bundle

                result = export_bundle(args.file, entry_names=args.entries)
                print(f"Encrypted bundle saved: {result}")
                print(f"  Contains {len(args.entries) if args.entries else 'all'} entries")
            else:
                commands.cmd_export(args.file, entries=args.entries, no_secrets=args.no_secrets)
        elif args.command == "import":
            _require_auth("import secrets")
            if args.decrypt:
                from ..bundle import import_bundle

                result = import_bundle(args.file, mode=args.mode)
                print(
                    f"\nImport complete: {result['created']} created, "
                    f"{result['updated']} updated, {result['skipped']} skipped"
                )
            else:
                importers.import_auto(
                    args.file,
                    mode=args.mode,
                    dry_run=args.dry_run,
                    filter_domain=args.filter,
                    allow_insecure=args.insecure,
                )
        elif args.command == "check":
            sys.exit(commands.cmd_check(args.entry, args.fields, quiet=args.quiet))
        elif args.command == "audit":
            if getattr(args, "verify", False):
                commands.cmd_audit(verify=True)
            elif args.clear:
                commands.cmd_audit(clear=True)
            elif args.summary:
                from ..health import cmd_audit_summary
                cmd_audit_summary()
            else:
                commands.cmd_audit(limit=args.limit)
        elif args.command == "generate":
            from ..generator import generate_password

            password = generate_password(args.length)
            if args.no_copy:
                print(password)
            else:
                from ..clipboard import copy_with_autoclear

                copy_with_autoclear(password, timeout_seconds=30)
                print(f"Generated {args.length}-char password (copied to clipboard, auto-clears in 30s)")
        elif args.command == "template":
            handle_template_command(args)
        elif args.command == "share":
            _require_auth("share secrets")
            entry = resolve_entry(args.entry, "Select entry to share")
            from ..sharing import cmd_share
            cmd_share(
                entry.name,
                output_path=args.output,
                shared_by=args.shared_by,
            )
        elif args.command == "receive":
            _require_auth("import secrets")
            from ..sharing import cmd_receive
            cmd_receive(args.file)
        elif args.command == "rotate":
            _require_auth("rotate secrets")
            entry = resolve_entry(args.entry, "Select entry to rotate")
            from ..health import cmd_rotate
            cmd_rotate(entry.name)
        elif args.command == "unwrap":
            mcp_commands.cmd_unwrap(
                tool=args.tool,
                server=args.server,
                config_path=args.config,
                restore_secrets=args.restore_secrets,
                dry_run=args.dry_run,
            )
        elif args.command == "config":
            from ..settings import cmd_config
            cmd_config(args.key, args.value)
        elif args.command == "mcp-serve":
            mcp_main()
        elif args.command == "completion":
            from .. import completion

            try:
                if args.bash:
                    completion.print_completion("bash")
                elif args.zsh:
                    completion.print_completion("zsh")
                elif args.fish:
                    completion.print_completion("fish")
                else:
                    completion.print_setup_instructions()
            except PasskeyError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
        elif args.command == "init":
            _require_auth("migrate secrets to keychain")
            mcp_commands.cmd_init(
                tool=args.tool,
                config_path=args.config,
                dry_run=args.dry_run,
                force=args.force,
                include_all=args.include_all,
                backup_path=args.backup,
            )
        elif args.command == "status":
            mcp_commands.cmd_status(tool=args.tool, json_output=args.json_output)
        elif args.command == "doctor":
            mcp_commands.cmd_doctor(deep=args.deep)
        elif args.command == "servers":
            mcp_commands.cmd_servers(tool=args.tool, json_output=args.json_output)
        elif args.command == "add":
            _require_auth("add credentials")
            mcp_commands.cmd_add(
                server=args.server,
                tool=getattr(args, "tool", None),
                fields=args.fields or None,
            )
        else:
            handle_onboarding_or_help(parser)

    except PasskeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
