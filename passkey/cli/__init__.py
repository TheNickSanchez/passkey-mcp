"""CLI package — main entry point for the passkey command."""

import difflib
import sys

from .. import commands, importers, mcp_commands
from ..interactive import InteractiveRequiredError, require_interactive, set_no_input
from ..keychain import PasskeyError, _get_entry
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
        "entry",
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
        "mcp",
        "mcp-serve",
        "init",
        "status",
        "doctor",
        "servers",
        "add",
        "completion",
        "help",
        "version",
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


def _dispatch_command(command: str | None, parser, args) -> None:
    """Dispatch a parsed top-level or noun-verb subcommand."""
    if command == "help":
        topics = list(getattr(args, "help_topic", None) or [])
        if not topics:
            parser.print_help()
            return
        parser.parse_args([*topics, "--help"])
        return

    if command == "version":
        from importlib.metadata import version as package_version

        print(f"passkey {package_version('passkey-mcp')}")
        return

    if command == "mcp":
        sub = getattr(args, "mcp_command", None)
        if not sub:
            mcp_sub = getattr(parser, "_mcp_group_parser", parser)
            mcp_sub.print_help()
            return
        _dispatch_command(sub, parser, args)
        return

    if command == "entry":
        sub = getattr(args, "entry_command", None)
        if not sub:
            entry_sub = getattr(parser, "_entry_group_parser", parser)
            entry_sub.print_help()
            return
        _dispatch_command(sub, parser, args)
        return

    if command == "new":
        # Name validation runs first inside cmd_new before require_interactive
        _require_auth("create entries")
        commands.cmd_new(
            name=getattr(args, "name", None),
            template_name=getattr(args, "template", None),
        )
    elif command == "list":
        commands.cmd_list(
            names_only=getattr(args, "names_only", False),
            json_output=getattr(args, "json_output", False),
        )
    elif command == "get":
        entry_arg = getattr(args, "entry", None)
        require_interactive(
            "passkey get",
            human_command=f"passkey get {entry_arg}" if entry_arg else "passkey get <entry>",
            alternative=(
                f"passkey info {entry_arg} --json  or  passkey run -q {entry_arg} -- <command>"
                if entry_arg
                else "passkey list --json  or  passkey run -q <entry> -- <command>"
            ),
        )
        _require_auth("access secrets")
        entry = resolve_entry(entry_arg, "Select entry to browse")
        if args.get_all:
            commands.cmd_get_all(entry)
        else:
            commands.cmd_get_interactive(entry)
    elif command == "edit":
        entry_arg = getattr(args, "entry", None)
        require_interactive(
            "passkey edit",
            human_command=f"passkey edit {entry_arg}" if entry_arg else "passkey edit <entry>",
        )
        _require_auth("edit entries")
        entry = resolve_entry(entry_arg, "Select entry to edit")
        commands.cmd_edit(entry)
    elif command == "delete":
        yes = bool(getattr(args, "yes", False))
        if not yes:
            require_interactive(
                "passkey delete",
                human_command=f"passkey delete {args.entry}",
                alternative=f"passkey delete {args.entry} --yes",
            )
        _require_auth("delete entries")
        entry = resolve_entry(args.entry, "Select entry to delete", fuzzy=False)
        commands.cmd_delete(entry.name, yes=yes)
    elif command == "info":
        commands.cmd_info(
            resolve_entry(getattr(args, "entry", None), "Select entry to view"),
            json_output=getattr(args, "json_output", False),
        )
    elif command == "clone":
        _require_auth("clone entries")
        source = resolve_entry(args.source, "Select entry to clone", fuzzy=False)
        commands.cmd_clone(source, getattr(args, "dest", None))
    elif command == "set-field":
        require_interactive(
            "passkey set-field",
            human_command=f"passkey entry set-field {args.entry} {args.field}",
        )
        _require_auth("modify entries")
        entry = resolve_entry(args.entry, "Select entry to update", fuzzy=False)
        commands.cmd_set_field(entry, args.field, None)
    elif command == "policy":
        if args.policy_value is not None:
            _require_auth("update entry policy")
        entry = resolve_entry(args.entry, "Select entry for policy", fuzzy=False)
        commands.cmd_policy(entry, args.policy_value)
    elif command == "lease":
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
    elif command == "plugin":
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
    elif command == "browser-fill":
        from ..browser_broker import cdp_autofill

        res = cdp_autofill(args.entry, args.cdp_url)
        print(f"Autofilled {', '.join(res['fields_injected'])} on {res['origin']}")
    elif command == "run":
        # Never auth-gated: headless path for MCP servers.
        # Protection comes from the OS keychain's own ACL prompts.
        handle_run_command(parser, args)
    elif command == "inject":
        _require_auth("inject secrets into file")
        commands.cmd_inject(
            args.in_file,
            args.out_file,
            to_stdout=args.stdout,
            force=args.force,
        )
    elif command == "mount":
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
    elif command == "hook":
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
    elif command == "export":
        if args.encrypt:
            require_interactive(
                "passkey export --encrypt",
                human_command=f"passkey export {args.file} --encrypt",
                alternative=f"passkey export {args.file} --no-secrets",
            )
            _require_auth("export secrets")
            from ..bundle import export_bundle

            result = export_bundle(args.file, entry_names=args.entries)
            print(f"Encrypted bundle saved: {result}")
            print(f"  Contains {len(args.entries) if args.entries else 'all'} entries")
        else:
            _require_auth("export secrets")
            commands.cmd_export(args.file, entries=args.entries, no_secrets=args.no_secrets)
    elif command == "import":
        if args.decrypt:
            require_interactive(
                "passkey import --decrypt",
                human_command=f"passkey import {args.file} --decrypt",
            )
            _require_auth("import secrets")
            from ..bundle import import_bundle

            result = import_bundle(args.file, mode=args.mode)
            print(
                f"\nImport complete: {result['created']} created, "
                f"{result['updated']} updated, {result['skipped']} skipped"
            )
        else:
            _require_auth("import secrets")
            importers.import_auto(
                args.file,
                mode=args.mode,
                dry_run=args.dry_run,
                filter_domain=args.filter,
                allow_insecure=args.insecure,
            )
    elif command == "check":
        sys.exit(
            commands.cmd_check(
                args.entry,
                args.fields,
                quiet=args.quiet,
                json_output=getattr(args, "json_output", False),
            )
        )
    elif command == "audit":
        if getattr(args, "verify", False):
            commands.cmd_audit(verify=True)
        elif args.clear:
            yes = bool(getattr(args, "yes", False))
            if not yes:
                require_interactive(
                    "passkey audit --clear",
                    human_command="passkey audit --clear",
                    alternative="passkey audit --clear --yes",
                )
            commands.cmd_audit(clear=True, yes=yes)
        elif args.summary:
            from ..health import cmd_audit_summary

            cmd_audit_summary()
        else:
            commands.cmd_audit(limit=args.limit)
    elif command == "generate":
        from ..generator import generate_password

        password = generate_password(args.length)
        if args.no_copy:
            print(password)
        else:
            from ..clipboard import copy_with_autoclear

            copy_with_autoclear(password, timeout_seconds=30)
            print(
                f"Generated {args.length}-char password (copied to clipboard, auto-clears in 30s)"
            )
    elif command == "template":
        handle_template_command(args)
    elif command == "share":
        require_interactive(
            "passkey share",
            human_command=f"passkey share {args.entry}",
        )
        _require_auth("share secrets")
        entry = resolve_entry(args.entry, "Select entry to share")
        from ..sharing import cmd_share

        cmd_share(
            entry.name,
            output_path=args.output,
            shared_by=args.shared_by,
        )
    elif command == "receive":
        require_interactive(
            "passkey receive",
            human_command=f"passkey receive {args.file}",
        )
        _require_auth("import secrets")
        from ..sharing import cmd_receive

        cmd_receive(args.file)
    elif command == "rotate":
        touch_only = bool(getattr(args, "touch_only", False))
        field_arg = getattr(args, "field", None)
        if not touch_only:
            human_cmd = f"passkey rotate {args.entry}" + (f" {field_arg}" if field_arg else "")
            require_interactive(
                "passkey rotate",
                human_command=human_cmd,
                alternative=f"passkey rotate {args.entry} --touch-only",
            )
        _require_auth("rotate secrets")
        entry = resolve_entry(args.entry, "Select entry to rotate")
        from ..health import cmd_rotate

        cmd_rotate(entry.name, field_arg, touch_only=touch_only)
    elif command == "unwrap":
        mcp_commands.cmd_unwrap(
            tool=args.tool,
            server=args.server,
            config_path=args.config,
            restore_secrets=args.restore_secrets,
            dry_run=args.dry_run,
        )
    elif command == "config":
        from ..settings import cmd_config

        cmd_config(args.key, args.value)
    elif command == "mcp-serve":
        from ..mcp_server import main as mcp_main

        mcp_main()
    elif command == "completion":
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
    elif command == "init":
        yes = bool(getattr(args, "yes", False))
        if not args.dry_run and not yes:
            tool_flag = f" --tool {args.tool}" if args.tool else ""
            require_interactive(
                "passkey init",
                human_command=f"passkey init{tool_flag}",
                alternative=f"passkey init --dry-run{tool_flag}  or  passkey init --yes{tool_flag}",
            )
        _require_auth("migrate secrets to keychain")
        mcp_commands.cmd_init(
            tool=args.tool,
            config_path=args.config,
            dry_run=args.dry_run,
            force=args.force,
            include_all=args.include_all,
            backup_path=args.backup,
            yes=yes,
        )
    elif command == "status":
        mcp_commands.cmd_status(tool=args.tool, json_output=args.json_output)
    elif command == "doctor":
        json_out = bool(getattr(args, "json_output", False))
        rc = mcp_commands.cmd_doctor(deep=args.deep, json_output=json_out)
        if json_out and rc != 0:
            sys.exit(rc)
    elif command == "servers":
        mcp_commands.cmd_servers(tool=args.tool, json_output=args.json_output)
    elif command == "add":
        tool_flag = f" --tool {args.tool}" if getattr(args, "tool", None) else ""
        require_interactive(
            "passkey add",
            human_command=f"passkey mcp add {args.server}{tool_flag}",
        )
        _require_auth("add credentials")
        mcp_commands.cmd_add(
            server=args.server,
            tool=getattr(args, "tool", None),
            fields=args.fields or None,
        )
    else:
        handle_onboarding_or_help(parser)


def main() -> None:
    """Main entry point with centralized error handling."""
    from ..dirs import run_migration_if_needed

    run_migration_if_needed()

    raw_argv = sys.argv[1:]
    pre_dash = raw_argv[: raw_argv.index("--")] if "--" in raw_argv else raw_argv
    early_no_input = "--no-input" in pre_dash

    set_no_input(early_no_input)
    try:
        non_no_input = [a for a in raw_argv if a != "--no-input"]
        if (
            "--" not in raw_argv
            and len(non_no_input) == 1
            and not non_no_input[0].startswith("-")
            and non_no_input[0] not in _KNOWN_COMMANDS
        ):
            entry_name = non_no_input[0]
            try:
                close_cmds = difflib.get_close_matches(
                    entry_name, sorted(_KNOWN_COMMANDS), n=1, cutoff=0.75
                )
                if close_cmds and _get_entry(entry_name, log_read=False) is None:
                    raise PasskeyError(
                        f"Unknown command '{entry_name}'. Did you mean 'passkey {close_cmds[0]}'?"
                    )
                require_interactive(
                    "passkey <entry>",
                    human_command=f"passkey {entry_name}",
                    alternative=(
                        f"passkey info {entry_name} --json  or  "
                        f"passkey run -q {entry_name} -- <command>"
                    ),
                )
                _require_auth("access secrets")
                entry = resolve_entry(entry_name, "Select entry to browse")
                commands.cmd_get_interactive(entry)
            except InteractiveRequiredError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(e.exit_code)
            except PasskeyError as e:
                print(f"Error: {e}", file=sys.stderr)
                sys.exit(1)
            except KeyboardInterrupt:
                print("\nOperation cancelled by user.", file=sys.stderr)
                sys.exit(1)
            except EOFError:
                print(
                    "\nError: Unexpected EOF on stdin (non-interactive session). "
                    "Pass required flags or ask the user to run this command in their terminal.",
                    file=sys.stderr,
                )
                sys.exit(1)
            return

        parser = create_parser()
        try:
            import argcomplete

            argcomplete.autocomplete(parser)
        except ImportError:
            pass

        args = parser.parse_args()
        if getattr(args, "no_input", False):
            set_no_input(True)

        try:
            _dispatch_command(args.command, parser, args)
        except InteractiveRequiredError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(e.exit_code)
        except PasskeyError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.", file=sys.stderr)
            sys.exit(1)
        except EOFError:
            print(
                "\nError: Unexpected EOF on stdin (non-interactive session). "
                "Pass required flags or ask the user to run this command in their terminal.",
                file=sys.stderr,
            )
            sys.exit(1)
    finally:
        set_no_input(False)


if __name__ == "__main__":
    main()
