"""CLI entry point for passkey."""

import argparse
import sys

from . import __version__, commands, importers, mcp_commands, runner
from .keychain import PasskeyError
from .mcp_server import main as mcp_main

SUBPARSER_GROUPS = [
    ("Entry Management", [
        "new", "list", "get", "edit", "delete", "info", "clone", "set-field", "check", "audit",
    ]),
    ("Secrets", [
        "generate", "rotate",
    ]),
    ("Templates", [
        "template",
    ]),
    ("Share & Receive", [
        "share", "receive",
    ]),
    ("Export & Import", [
        "export", "import",
    ]),
    ("Run", [
        "run",
    ]),
    ("MCP Integration", [
        "init", "status", "doctor", "servers", "add",
    ]),
    ("Utilities", [
        "completion", "mcp-serve",
    ]),
    ("Legacy", [
        "claude",
    ]),
]


def _entry_completer(**kwargs):
    """Return entry names for shell tab completion. Silent on any error."""
    try:
        from .keychain import list_entries

        return list_entries()
    except Exception:
        return []


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="passkey",
        usage="%(prog)s [-h] [--version] <command> [<args>]",
        description="Manage secrets in system keychain with MCP integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  passkey new                               Create a new entry interactively
  passkey list                              List all entry names
  passkey get slack                         Browse and copy fields from an entry
  passkey get slack --all                   Copy all fields to clipboard
  passkey edit jamf                         Edit an existing entry
  passkey delete cortex_xdr                Delete an entry
  passkey info slack                        Show entry details and field names
  passkey set-field cortex_xdr api_key      Add or update a field
  passkey clone slack slack_prod            Clone an entry
  passkey check github GITHUB_TOKEN         Verify entry has required fields
  passkey generate --length 64              Generate a random secret
  passkey run slack -- python app.py        Run app.py with slack secrets as env vars
  passkey export backup.json                Export all entries to file
  passkey import backup.json                Import (auto-detects format)
  passkey share github --output gh.passkey  Share an entry via encrypted bundle
  passkey init                              Migrate MCP config secrets to keychain
  passkey init --tool vscode                Migrate VS Code MCP config specifically
  passkey status                            Show security status across all tools
  passkey doctor --deep                     Run extended diagnostics
  passkey servers                           List MCP servers across tools
  passkey completion --bash                 Print shell completion script
  passkey slack                             Fuzzy-match and browse entry 'slack'
        """,
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # new
    subparsers.add_parser("new", help="Create a new entry interactively")

    # list
    list_parser = subparsers.add_parser("list", help="List all entry names")
    list_parser.add_argument(
        "--names-only",
        action="store_true",
        dest="names_only",
        help="Print entry names only (one per line)",
    )

    # get
    get_parser = subparsers.add_parser("get", help="Browse and copy fields from an entry")
    get_parser.add_argument(
        "entry",
        nargs="?",
        default="",
        metavar="ENTRY",
        help="Entry name (interactive selector if omitted)",
    )
    get_parser.add_argument(
        "--all",
        "-a",
        dest="get_all",
        action="store_true",
        help="Copy all fields to clipboard instead of interactive picker",
    )

    # edit
    edit_parser = subparsers.add_parser("edit", help="Edit an existing entry")
    edit_parser.add_argument("entry", nargs="?", default="", metavar="ENTRY", help="Entry name")

    # delete
    delete_parser = subparsers.add_parser("delete", help="Delete an entry")
    delete_parser.add_argument(
        "entry", nargs="?", default="", metavar="ENTRY", help="Entry name (exact match required)"
    )

    # info
    info_parser = subparsers.add_parser("info", help="Show entry details and field names")
    info_parser.add_argument("entry", nargs="?", default="", metavar="ENTRY", help="Entry name")

    # clone
    clone_parser = subparsers.add_parser("clone", help="Clone an entry")
    clone_parser.add_argument("source", metavar="SOURCE", help="Source entry name")
    clone_parser.add_argument(
        "dest",
        nargs="?",
        default=None,
        metavar="DEST",
        help="Destination entry name (prompted if omitted)",
    )

    # set-field
    set_field_parser = subparsers.add_parser("set-field", help="Add or update a field on an entry")
    set_field_parser.add_argument("entry", metavar="ENTRY", help="Entry name")
    set_field_parser.add_argument("field", metavar="FIELD", help="Field name")

    # run
    run_parser = subparsers.add_parser("run", help="Run command with secrets as env vars")
    run_parser.add_argument("args", nargs=argparse.REMAINDER, help="entries... -- command")

    # export
    export_parser = subparsers.add_parser("export", help="Export entries to file")
    export_parser.add_argument("file", help="Output file path (use - for stdout)")
    export_parser.add_argument("--entries", nargs="+", help="Specific entries to export")
    export_parser.add_argument("--no-secrets", action="store_true", help="Export metadata only")
    export_parser.add_argument(
        "--encrypt", action="store_true", help="Export as encrypted bundle (.passkey.enc)"
    )

    # import
    import_parser = subparsers.add_parser("import", help="Import entries (auto-detects format)")
    import_parser.add_argument("file", help="File to import")
    import_parser.add_argument(
        "--mode",
        choices=["skip", "overwrite", "merge"],
        default="skip",
        help="How to handle existing entries",
    )
    import_parser.add_argument("--dry-run", action="store_true", help="Preview without importing")
    import_parser.add_argument(
        "--filter", metavar="DOMAIN", help="Filter by domain (Chrome CSV only)"
    )
    import_parser.add_argument(
        "--insecure",
        action="store_true",
        help="Allow importing from files with insecure permissions",
    )
    import_parser.add_argument(
        "--decrypt", action="store_true", help="Import from encrypted bundle (.passkey.enc)"
    )
    import_parser.add_argument(
        "--setup-claude",
        action="store_true",
        help="Also rewrite Claude MCP config to use passkey wrapper",
    )

    # check
    check_parser = subparsers.add_parser(
        "check", help="Verify an entry has required fields (exits non-zero if missing)"
    )
    check_parser.add_argument("entry", help="Entry name")
    check_parser.add_argument("fields", nargs="+", metavar="FIELD", help="Required field names")
    check_parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress output, exit code only"
    )

    # audit
    audit_parser = subparsers.add_parser("audit", help="View or clear audit log")
    audit_parser.add_argument("--limit", type=int, default=20, help="Number of entries to show")
    audit_parser.add_argument("--clear", action="store_true", help="Clear the audit log")
    audit_parser.add_argument("--summary", action="store_true", help="Show aggregate summary")

    # generate
    generate_parser = subparsers.add_parser("generate", help="Generate a random secret")
    generate_parser.add_argument(
        "--length", "-l", type=int, default=32, help="Password length (default: 32)"
    )
    generate_parser.add_argument(
        "--no-copy", action="store_true", help="Print only, don't copy to clipboard"
    )

    # template
    template_parser = subparsers.add_parser("template", help="Manage secret templates")
    template_subparsers = template_parser.add_subparsers(dest="template_command")
    template_subparsers.add_parser("list", help="List all templates")
    template_show = template_subparsers.add_parser("show", help="Show template details")
    template_show.add_argument("template_name", help="Template name")
    template_apply = template_subparsers.add_parser("apply", help="Create entry from template")
    template_apply.add_argument("template_name", help="Template name")
    template_apply.add_argument("entry_name", nargs="?", help="Entry name (defaults to template name)")
    template_subparsers.add_parser("add", help="Save current entry as template")

    # share
    share_parser = subparsers.add_parser("share", help="Share an entry as an encrypted bundle")
    share_parser.add_argument("entry", nargs="?", default="", metavar="ENTRY", help="Entry to share")
    share_parser.add_argument("--output", "-o", help="Output file path")
    share_parser.add_argument("--from", dest="shared_by", help="Sender name")

    # receive
    receive_parser = subparsers.add_parser("receive", help="Import entries from an encrypted bundle")
    receive_parser.add_argument("file", help="Bundle file path (.enc)")

    # mcp-serve
    subparsers.add_parser("mcp-serve", help="Start MCP server")

    # completion
    completion_parser = subparsers.add_parser(
        "completion", help="Print shell tab completion scripts"
    )
    completion_parser.add_argument(
        "--bash", action="store_true", help="Print bash completion script"
    )
    completion_parser.add_argument(
        "--zsh", action="store_true", help="Print zsh completion script"
    )
    completion_parser.add_argument(
        "--fish", action="store_true", help="Print fish completion script"
    )

    # init (top-level, tool-agnostic)
    init_parser = subparsers.add_parser("init", help="Migrate MCP config secrets to keychain")
    init_parser.add_argument(
        "tool",
        nargs="?",
        default=None,
        help="Tool to migrate (claude, gemini, vscode, cursor, etc.)",
    )
    init_parser.add_argument("--config", help="Path to config file")
    init_parser.add_argument("--dry-run", action="store_true", help="Preview changes")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing entries")
    init_parser.add_argument("--include-all", action="store_true", help="Include all servers")
    init_parser.add_argument("--backup", help="Backup path for config")

    # status (top-level, tool-agnostic)
    status_parser = subparsers.add_parser("status", help="Show security status across tools")
    status_parser.add_argument("tool", nargs="?", default=None, help="Specific tool to check")
    status_parser.add_argument(
        "--json", dest="json_output", action="store_true", help="Output as JSON"
    )

    # doctor
    doctor_parser = subparsers.add_parser("doctor", help="Run diagnostics (--deep for entry age analysis)")
    doctor_parser.add_argument("--deep", action="store_true", help="Extended diagnostics with entry age analysis")

    # servers (top-level, tool-agnostic)
    servers_parser = subparsers.add_parser("servers", help="List MCP servers across tools")
    servers_parser.add_argument(
        "tool", nargs="?", default=None, help="Specific tool to list servers for"
    )
    servers_parser.add_argument(
        "--json", dest="json_output", action="store_true", help="Output as JSON"
    )

    # rotate
    rotate_parser = subparsers.add_parser("rotate", help="Update last-rotated timestamp on an entry")
    rotate_parser.add_argument("entry", nargs="?", default="", metavar="ENTRY", help="Entry name")

    # add (top-level)
    add_parser = subparsers.add_parser("add", help="Add credentials for an MCP server")
    add_parser.add_argument("server", help="Server name")
    add_parser.add_argument("fields", nargs="*", help="Field names to set (values will be prompted)")
    add_parser.add_argument("--tool", help="Target tool config to update")

    # claude (backward-compat alias)
    claude_parser = subparsers.add_parser("claude", help="Claude integration (backward compat)")
    claude_subparsers = claude_parser.add_subparsers(dest="claude_command")

    claude_init = claude_subparsers.add_parser("init", help="Initialize passkey for Claude")
    claude_init.add_argument("--config", help="Path to Claude config file")
    claude_init.add_argument("--dry-run", action="store_true", help="Preview changes")
    claude_init.add_argument("--force", action="store_true", help="Overwrite existing entries")
    claude_init.add_argument("--include-all", action="store_true", help="Include all servers")
    claude_init.add_argument("--backup", help="Backup path for config")

    claude_status = claude_subparsers.add_parser("status", help="Show Claude MCP security status")
    claude_status.add_argument(
        "--json", dest="json_output", action="store_true", help="Output as JSON"
    )

    # Attach completers
    try:
        for p in (get_parser, edit_parser, delete_parser, info_parser):
            for action in p._actions:
                if getattr(action, "dest", None) == "entry":
                    action.completer = _entry_completer
        for action in clone_parser._actions:
            if getattr(action, "dest", None) == "source":
                action.completer = _entry_completer
        for action in set_field_parser._actions:
            if getattr(action, "dest", None) == "entry":
                action.completer = _entry_completer
        for action in check_parser._actions:
            if getattr(action, "dest", None) == "entry":
                action.completer = _entry_completer
    except Exception:
        pass

    def _format_help():
        """Custom help output with grouped subcommands."""
        lines = []
        lines.append(f"usage: {parser.prog} [-h] [--version] <command> [<args>]\n")
        if parser.description:
            lines.append(f"{parser.description}\n")
        option_actions = [a for a in parser._actions if a.option_strings]
        if option_actions:
            lines.append("options:\n")
            for action in option_actions:
                opts = ", ".join(action.option_strings)
                h = action.help or ""
                lines.append(f"  {opts:<22}  {h}\n")
        subparsers_action = None
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                subparsers_action = action
                break
        if subparsers_action:
            help_map = {}
            for choice in getattr(subparsers_action, '_choices_actions', ()):
                help_map[choice.dest] = choice.help or ''
            if not help_map:
                for name, sub in subparsers_action._name_parser_map.items():
                    help_map[name] = getattr(sub, 'help', '') or ''
            lines.append("\ncommands:\n")
            for group_name, cmd_names in SUBPARSER_GROUPS:
                entries = []
                for name in cmd_names:
                    if name in subparsers_action._name_parser_map:
                        entries.append((name, help_map.get(name, "")))
                if entries:
                    lines.append(f"\n  {group_name}:\n")
                    width = max(len(n) for n, _ in entries)
                    for name, h in entries:
                        lines.append(f"    {name:<{width}}  {h}\n")
        if parser.epilog:
            lines.append(f"\n{parser.epilog.strip()}\n")
        return "".join(lines)

    parser.format_help = _format_help
    return parser


def resolve_entry(entry_arg: str | None, prompt: str = "Select an entry", fuzzy: bool = True):
    """Resolve entry argument, falling back to interactive selector if needed."""
    from .interactive import is_interactive, select_entry
    from .keychain import get_entry

    resolved_name = None

    if entry_arg:
        entry = get_entry(entry_arg)
        if entry:
            return entry
        if not fuzzy:
            raise PasskeyError(f"Entry '{entry_arg}' not found.")
        resolved_name = entry_arg

    if is_interactive():
        resolved_name = select_entry(prompt, filter_prefix=resolved_name if fuzzy else "")
    else:
        raise PasskeyError(f"Entry '{entry_arg}' not found in non-interactive session.")

    final_entry = get_entry(resolved_name)
    if not final_entry:
        raise PasskeyError(f"Failed to fetch details for entry '{resolved_name}'.")

    return final_entry


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
        "mcp-serve",
        "claude",
        "init",
        "status",
        "doctor",
        "servers",
        "add",
        "completion",
    }
)


def _require_auth(operation: str) -> None:
    """Require OS authentication for sensitive operations."""
    from .auth import require_auth

    require_auth(operation)


def main() -> None:
    """Main entry point with centralized error handling."""
    from .dirs import run_migration_if_needed

    run_migration_if_needed()

    # Positional fallback: passkey <entry> (not a known subcommand, not a flag)
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
            _require_auth("run with secrets")
            handle_run_command(parser, args)
        elif args.command == "export":
            _require_auth("export secrets")
            if args.encrypt:
                from .bundle import export_bundle

                result = export_bundle(args.file, entry_names=args.entries)
                print(f"Encrypted bundle saved: {result}")
                print(f"  Contains {len(args.entries) if args.entries else 'all'} entries")
            else:
                commands.cmd_export(args.file, entries=args.entries, no_secrets=args.no_secrets)
        elif args.command == "import":
            _require_auth("import secrets")
            if args.decrypt:
                from .bundle import import_bundle

                result = import_bundle(args.file, mode=args.mode, setup_claude=args.setup_claude)
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
            commands.cmd_check(args.entry, args.fields, quiet=args.quiet)
        elif args.command == "audit":
            if args.clear:
                commands.cmd_audit(clear=True)
            elif args.summary:
                from .health import cmd_audit_summary
                cmd_audit_summary()
            else:
                commands.cmd_audit(limit=args.limit)
        elif args.command == "generate":
            from .generator import generate_password

            password = generate_password(args.length)
            if args.no_copy:
                print(password)
            else:
                from .clipboard import copy_with_autoclear

                copy_with_autoclear(password, timeout_seconds=30)
                print(f"Generated {args.length}-char password (copied to clipboard, auto-clears in 30s)")
        elif args.command == "template":
            handle_template_command(args)
        elif args.command == "share":
            _require_auth("share secrets")
            entry = resolve_entry(args.entry, "Select entry to share")
            from .sharing import cmd_share
            cmd_share(
                entry.name,
                output_path=args.output,
                shared_by=args.shared_by,
            )
        elif args.command == "receive":
            _require_auth("import secrets")
            from .sharing import cmd_receive
            cmd_receive(args.file)
        elif args.command == "rotate":
            _require_auth("rotate secrets")
            entry = resolve_entry(args.entry, "Select entry to rotate")
            from .health import cmd_rotate
            cmd_rotate(entry.name)
        elif args.command == "mcp-serve":
            mcp_main()
        elif args.command == "completion":
            from . import completion

            if args.bash:
                completion.print_completion("bash")
            elif args.zsh:
                completion.print_completion("zsh")
            elif args.fish:
                completion.print_completion("fish")
            else:
                completion.print_setup_instructions()
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
            if args.deep:
                from .health import cmd_doctor_deep
                cmd_doctor_deep()
            else:
                mcp_commands.cmd_doctor()
        elif args.command == "servers":
            mcp_commands.cmd_servers(tool=args.tool, json_output=args.json_output)
        elif args.command == "add":
            _require_auth("add credentials")
            mcp_commands.cmd_add(
                server=args.server,
                tool=getattr(args, "tool", None),
                fields=args.fields or None,
            )
        elif args.command == "claude":
            handle_claude_command(parser, args)
        else:
            handle_onboarding_or_help(parser)

    except PasskeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)


def handle_run_command(parser, args):
    """Handler for the 'run' subcommand."""
    from .interactive import is_interactive, select_multiple_entries

    run_args = args.args
    if "--" not in run_args:
        parser.error("Usage: passkey run <entries...> -- <command>")

    sep_idx = run_args.index("--")
    entries = run_args[:sep_idx]
    cmd = run_args[sep_idx + 1 :]

    if not entries:
        if is_interactive():
            entries = select_multiple_entries("Select entries to load secrets from")
        else:
            raise PasskeyError("No entries specified for 'run' in non-interactive mode.")

    if not cmd:
        raise PasskeyError("No command specified after --")

    runner.run_with_secrets(entries, cmd)


def handle_claude_command(parser, args):
    """Handler for backward-compat 'claude' subcommands."""
    if args.claude_command == "init":
        _require_auth("migrate secrets to keychain")
        mcp_commands.cmd_init(
            tool="claude",
            config_path=args.config,
            dry_run=args.dry_run,
            force=args.force,
            include_all=args.include_all,
            backup_path=args.backup,
        )
    elif args.claude_command == "status":
        mcp_commands.cmd_status(tool="claude", json_output=args.json_output)
    else:
        claude_parser = parser._subparsers._group_actions[0].choices["claude"]
        claude_parser.parse_args(["claude", "--help"])


def handle_template_command(args):
    """Handler for the 'template' subcommands."""
    from .templates import get_template, list_templates

    if args.template_command == "list":
        templates = list_templates()
        if not templates:
            print("No templates found")
            return
        name_w = max(len(t["name"]) for t in templates)
        for t in templates:
            field_count = len(t.get("fields", []))
            print(f"  {t['name']:<{name_w}}  {field_count} field{'s' if field_count != 1 else ''}  {t.get('description', '')}")

    elif args.template_command == "show":
        template = get_template(args.template_name)
        if not template:
            raise PasskeyError(f"Template '{args.template_name}' not found")
        print(f"Template: {template['name']}")
        print(f"Description: {template.get('description', '')}")
        print("\nFields:")
        for field in template.get("fields", []):
            secret_marker = " (secret)" if field.get("secret") else ""
            generate_marker = " [generate]" if field.get("generate") else ""
            desc = field.get("description", "")
            print(f"  {field['name']}{secret_marker}{generate_marker}")
            if desc:
                print(f"    {desc}")

    elif args.template_command == "apply":
        _require_auth("create entries from template")
        template = get_template(args.template_name)
        if not template:
            raise PasskeyError(f"Template '{args.template_name}' not found")
        entry_name = args.entry_name or template["name"]
        commands.cmd_template_apply(template, entry_name)

    elif args.template_command == "add":
        _require_auth("save template")
        _save_entry_as_template()

    else:
        raise PasskeyError("Usage: passkey template [list|show|apply|add]")


def _save_entry_as_template() -> None:
    """Save an existing entry as a custom template."""
    from .interactive import is_interactive, select_entry
    from .templates import save_custom_template

    entry = select_entry("Select entry to save as template")
    if not entry:
        return

    if is_interactive():
        import questionary
        name = questionary.text("Template name:", default=entry.name).ask()
    else:
        name = input(f"Template name [{entry.name}]: ").strip() or entry.name

    if not name:
        raise PasskeyError("Template name cannot be empty")

    description = input("Description (optional): ").strip() if not is_interactive() else ""
    if is_interactive():
        description = questionary.text("Description:", default="").ask() or ""

    template = {
        "name": name,
        "description": description,
        "fields": [
            {
                "name": field_name,
                "description": "",
                "secret": True,
            }
            for field_name in sorted(entry.fields.keys())
        ],
    }

    save_custom_template(template)
    print(f"Saved template '{name}' with {len(template['fields'])} field(s)")


def handle_onboarding_or_help(parser):
    """Handle first-time use or show help."""
    from .keychain import list_entries

    try:
        entries = list_entries()
    except PasskeyError:
        parser.print_help()
        return

    if not entries:
        _show_onboarding()
    else:
        parser.print_help()


def _show_onboarding():
    """Interactive onboarding flow for first-time users."""
    from .interactive import is_interactive

    print()
    print("  ┌─────────────────────────────────────────────┐")
    print("  │           Welcome to passkey                 │")
    print("  │  Secrets in your keychain. Not in config.    │")
    print("  └─────────────────────────────────────────────┘")
    print()
    print("  Passkey stores API keys, tokens, and passwords")
    print("  in your system keychain and injects them as")
    print("  environment variables when you need them.")
    print()

    if not is_interactive():
        print("  Run 'passkey new' to create your first entry.")
        return

    print("  Things you can do:")
    print("    passkey new           Save your first secret")
    print("    passkey list          List all saved entries")
    print("    passkey run X -- cmd  Run a command with secrets")
    print("    passkey completion    Set up tab completion")
    print("    passkey --help        See all commands")
    print()

    try:
        choice = input("  Create your first entry now? [Y/n] ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n")
        return

    if choice in ("", "y", "yes"):
        print()
        try:
            commands.cmd_new()
        except (PasskeyError, KeyboardInterrupt, EOFError):
            print("\n  No worries. Run 'passkey new' when you're ready.\n")
            return

        print()
        print("  Nice! Your first entry is saved.")
        print("  Try these next:")
        print()
        print("    passkey list              See your entries")
        print("    passkey get <name>        Browse and copy a field")
        print("    passkey run <name> -- cmd Run something with secrets")
        print("    passkey completion        Set up tab completion")
        print()
    else:
        print()
        print("  No worries. Run 'passkey new' when you're ready.\n")


if __name__ == "__main__":
    main()
