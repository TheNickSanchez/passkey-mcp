"""CLI command handlers — all sys.exit lives in the outermost main() layer."""

import sys

from .. import commands, mcp_commands, runner
from ..keychain import PasskeyError


def resolve_entry(entry_arg: str | None, prompt: str = "Select an entry", fuzzy: bool = True):
    """Resolve entry argument, falling back to interactive selector if needed."""
    from ..interactive import is_interactive, select_entry
    from ..keychain import get_entry

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


def handle_run_command(parser, args):
    """Handler for the 'run' subcommand."""
    from ..interactive import is_interactive, select_multiple_entries

    run_args = list(args.args)
    if "--" not in run_args:
        parser.error("Usage: passkey run [-q|--quiet] [--no-masking] <entries...> -- <command>")

    sep_idx = run_args.index("--")
    pre_sep = run_args[:sep_idx]
    cmd = run_args[sep_idx + 1 :]

    no_masking = bool(getattr(args, "no_masking", False))
    quiet = bool(getattr(args, "quiet", False))
    env_files: list[str] = list(getattr(args, "env_files", None) or [])
    entries: list[str] = []
    idx = 0
    while idx < len(pre_sep):
        token = pre_sep[idx]
        if token == "--no-masking":
            no_masking = True
        elif token in ("-q", "--quiet"):
            quiet = True
        elif token == "--env-file":
            if idx + 1 >= len(pre_sep):
                raise PasskeyError("--env-file requires a path argument")
            env_files.append(pre_sep[idx + 1])
            idx += 2
            continue
        elif token.startswith("--env-file="):
            env_files.append(token.split("=", 1)[1])
        else:
            entries.append(token)
        idx += 1

    if not entries and not env_files:
        import os as _os

        from ..references import is_reference

        has_inherited_refs = any(is_reference(v) for v in _os.environ.values())
        if not has_inherited_refs:
            if is_interactive():
                entries = select_multiple_entries("Select entries to load secrets from")
            else:
                raise PasskeyError("No entries specified for 'run' in non-interactive mode.")

    if not cmd:
        raise PasskeyError("No command specified after --")

    rc = runner.run_with_secrets(
        entries,
        cmd,
        no_masking=no_masking,
        quiet=quiet,
        env_files=env_files,
    )
    sys.exit(rc)


def handle_template_command(args):
    """Handler for the 'template' subcommands."""
    from ..templates import get_template, list_templates

    _require_auth = _get_require_auth()

    if args.template_command == "list":
        templates = list_templates()
        if not templates:
            print("No templates found")
            return
        name_w = max(len(t["name"]) for t in templates)
        for t in templates:
            field_count = len(t.get("fields", []))
            print(
                f"  {t['name']:<{name_w}}  {field_count} field{'s' if field_count != 1 else ''}  {t.get('description', '')}"
            )

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
    from ..interactive import PASSKEY_STYLE, is_interactive
    from ..templates import save_custom_template

    entry = resolve_entry(None, "Select entry to save as template")
    if not entry:
        return

    if is_interactive():
        import questionary

        name = questionary.text(
            "Template name:", default=entry.name, style=PASSKEY_STYLE
        ).ask()
    else:
        name = input(f"Template name [{entry.name}]: ").strip() or entry.name

    if not name:
        raise PasskeyError("Template name cannot be empty")

    if is_interactive():
        import questionary

        description = questionary.text("Description:", default="", style=PASSKEY_STYLE).ask() or ""
    else:
        description = input("Description (optional): ").strip()

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


def _print_quickstart_examples() -> None:
    """Print concise quickstart examples for new users."""
    print()
    print("  Quickstart Examples:")
    print("    passkey new stripe                        Create an entry and paste secrets")
    print("    passkey stripe                            Browse and copy fields to clipboard")
    print("    passkey run stripe -- python app.py       Inject secrets as env vars at runtime")
    print("    passkey init                              Migrate plaintext MCP server configs")
    print("    passkey inject -i .env.tpl -o .env        Render {{ passkey://... }} templates")
    print("    passkey --help                            View all commands and categories")
    print()


def handle_onboarding_or_help(parser) -> None:
    """Context-aware bare ``passkey`` router across States A, B, and C."""
    from ..interactive import PASSKEY_STYLE, is_interactive
    from ..keychain import list_entries

    try:
        entries = list_entries()
    except PasskeyError:
        parser.print_help()
        return

    # State C: Entries already exist -> fuzzy entry browser on TTY, help on non-TTY
    if entries:
        if not is_interactive():
            parser.print_help()
            return
        _require_auth = _get_require_auth()
        _require_auth("access secrets")
        entry = resolve_entry(None, "Select entry to browse")
        commands.cmd_get_interactive(entry)
        return

    # 0 entries: check for exposed MCP configs on disk
    exposed = mcp_commands.detect_exposed_mcp_servers()

    if not is_interactive():
        print()
        print("  passkey — Secrets in your OS keychain, not in config files")
        if exposed:
            print(
                f"  Detected {len(exposed)} MCP server(s) with plaintext secrets. "
                "Run 'passkey init' to migrate them."
            )
        else:
            print("  Run 'passkey new' to create your first secret, or 'passkey --help'.")
        print()
        return

    import questionary

    _require_auth = _get_require_auth()

    # State A: 0 entries + exposed MCP servers detected
    if exposed:
        print()
        print("  passkey — Secrets in your OS keychain, not in config files")
        print("  ──────────────────────────────────────────────────────────")
        print(f"  Found {len(exposed)} MCP server(s) with plaintext credentials:")
        for item in exposed:
            keys = ", ".join(item["secret_keys"][:3])
            if len(item["secret_keys"]) > 3:
                keys += f" (+{len(item['secret_keys']) - 3} more)"
            print(f"    • {item['display_name']} ({item['config_path']}): {item['server']} [{keys}]")
        print()

        action = questionary.select(
            "Migrate these secrets into your OS keychain now? [Y/n]",
            choices=[
                questionary.Choice(
                    "Migrate exposed MCP secrets now (passkey init)", "init"
                ),
                questionary.Choice("Create a new entry manually (passkey new)", "new"),
                questionary.Choice("Skip for now", "skip"),
            ],
            style=PASSKEY_STYLE,
            use_jk_keys=False,
        ).ask()

        if action == "init":
            print()
            _require_auth("migrate secrets to keychain")
            tools = list(dict.fromkeys(item["tool"] for item in exposed))
            paths = list(dict.fromkeys(item["config_path"] for item in exposed))
            tool_arg = tools[0] if len(tools) == 1 else None
            cfg_arg = str(paths[0]) if len(paths) == 1 else None
            mcp_commands.cmd_init(tool=tool_arg, config_path=cfg_arg)
        elif action == "new":
            print()
            _require_auth("create entries")
            commands.cmd_new()
        else:
            print("\n  Run 'passkey init' or 'passkey new' whenever you're ready.\n")
        return

    # State B: 0 entries + no exposed MCP servers
    print()
    print("  passkey — Secrets in your OS keychain, not in config files")
    print("  ──────────────────────────────────────────────────────────")
    print("  Store API keys and tokens in your OS keychain and inject them")
    print("  into CLIs and MCP servers on demand.")
    print()

    action = questionary.select(
        "What would you like to do?",
        choices=[
            questionary.Choice("Create your first secret (passkey new)", "new"),
            questionary.Choice("Show quickstart examples", "examples"),
            questionary.Choice("Exit", "quit"),
        ],
        style=PASSKEY_STYLE,
        use_jk_keys=False,
    ).ask()

    if action == "new":
        print()
        _require_auth("create entries")
        commands.cmd_new()
    elif action == "examples":
        _print_quickstart_examples()
    else:
        print("\n  Run 'passkey new' when you're ready.\n")


def _get_require_auth():
    """Lazily import _require_auth to avoid circular imports at module load."""
    from ..cli import _require_auth

    return _require_auth
