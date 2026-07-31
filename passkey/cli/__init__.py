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
        "run",
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
        elif args.command == "run":
            # Never auth-gated: headless path for MCP servers.
            # Protection comes from the OS keychain's own ACL prompts.
            handle_run_command(parser, args)
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
            if args.clear:
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
