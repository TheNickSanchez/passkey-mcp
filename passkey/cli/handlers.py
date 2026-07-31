"""CLI command handlers — all sys.exit lives in the outermost main() layer."""

import sys

from .. import commands, runner
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

    rc = runner.run_with_secrets(entries, cmd)
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
    from ..interactive import is_interactive, select_entry
    from ..templates import save_custom_template

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
    from ..keychain import list_entries

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
    from ..interactive import is_interactive

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


def _get_require_auth():
    """Lazily import _require_auth to avoid circular imports at module load."""
    from ..cli import _require_auth
    return _require_auth
