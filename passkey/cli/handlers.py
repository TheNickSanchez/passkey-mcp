"""CLI command handlers — all sys.exit lives in the outermost main() layer."""

import json
import sys

from .. import commands, mcp_commands, runner
from ..keychain import PasskeyError


def resolve_entry(
    entry_arg: str | None,
    prompt: str = "Select an entry",
    fuzzy: bool = True,
    *,
    log_read: bool = True,
):
    """Resolve entry argument, falling back to interactive selector if needed."""
    from ..interactive import (
        InteractiveRequiredError,
        can_prompt_interactively,
        select_entry,
    )
    from ..keychain import _get_entry, get_entry

    fetch = get_entry if log_read else (lambda n: _get_entry(n, log_read=False))
    resolved_name = None

    if entry_arg:
        entry = fetch(entry_arg)
        if entry:
            return entry
        if not fuzzy or not can_prompt_interactively():
            raise PasskeyError(
                f"Entry '{entry_arg}' not found. "
                f"Ask the user to run 'passkey new {entry_arg}' in their terminal "
                "(never ask them to paste secrets into chat).",
                error_code="ENTRY_NOT_FOUND",
                entry=entry_arg,
                remediation_command=f"passkey new {entry_arg}",
            )
        resolved_name = entry_arg
    else:
        if not can_prompt_interactively():
            raise InteractiveRequiredError(
                "No entry name specified in non-interactive mode.\n"
                "  Pass an explicit <entry> name, or run 'passkey list --json' to discover entries.",
                error_code="INTERACTIVE_REQUIRED",
                remediation_command="passkey list --json",
            )

    resolved_name = select_entry(prompt, filter_prefix=resolved_name if fuzzy else "")

    final_entry = fetch(resolved_name)
    if not final_entry:
        raise PasskeyError(
            f"Entry '{resolved_name}' not found. "
            f"Ask the user to run 'passkey new {resolved_name}' in their terminal "
            "(never ask them to paste secrets into chat).",
            error_code="ENTRY_NOT_FOUND",
            entry=resolved_name,
            remediation_command=f"passkey new {resolved_name}",
        )

    return final_entry


def resolve_entry_meta(
    entry_arg: str | None,
    prompt: str = "Select an entry",
    fuzzy: bool = True,
):
    """Resolve secret-free EntryMeta without touching the OS Keychain when hydrated."""
    from ..interactive import (
        InteractiveRequiredError,
        can_prompt_interactively,
        select_entry,
    )
    from ..keychain import get_entry_meta

    resolved_name = None

    if entry_arg:
        meta = get_entry_meta(entry_arg)
        if meta:
            return meta
        if not fuzzy or not can_prompt_interactively():
            raise PasskeyError(
                f"Entry '{entry_arg}' not found. "
                f"Ask the user to run 'passkey new {entry_arg}' in their terminal "
                "(never ask them to paste secrets into chat).",
                error_code="ENTRY_NOT_FOUND",
                entry=entry_arg,
                remediation_command=f"passkey new {entry_arg}",
            )
        resolved_name = entry_arg
    else:
        if not can_prompt_interactively():
            raise InteractiveRequiredError(
                "No entry name specified in non-interactive mode.\n"
                "  Pass an explicit <entry> name, or run 'passkey list --json' to discover entries.",
                error_code="INTERACTIVE_REQUIRED",
                remediation_command="passkey list --json",
            )

    resolved_name = select_entry(prompt, filter_prefix=resolved_name if fuzzy else "")

    final_meta = get_entry_meta(resolved_name)
    if not final_meta:
        raise PasskeyError(
            f"Entry '{resolved_name}' not found. "
            f"Ask the user to run 'passkey new {resolved_name}' in their terminal "
            "(never ask them to paste secrets into chat).",
            error_code="ENTRY_NOT_FOUND",
            entry=resolved_name,
            remediation_command=f"passkey new {resolved_name}",
        )

    return final_meta


def _print_preflight_report(report: dict) -> None:
    """Render a human-readable preflight summary for ``passkey run --dry-run``."""
    status_label = "READY" if report["ready"] else "NOT READY"
    print(f"Preflight status: {status_label}")
    if report["entries_found"]:
        found_str = ", ".join(
            f"{e['name']} (policy={e['policy']})" for e in report["entries_found"]
        )
        print(f"Entries found:    {found_str}")
    if report["entries_missing"]:
        print(f"Entries missing:  {', '.join(report['entries_missing'])}")
    if report["env_files"]:
        print(f"Env files:        {', '.join(report['env_files'])}")
    if report["env_files_missing"]:
        print(f"Missing files:    {', '.join(report['env_files_missing'])}")
    if report["references_checked"]:
        print(
            f"References:       {len(report['references_valid'])} valid, "
            f"{len(report['references_invalid'])} invalid"
        )
    if report["injected_env_vars"]:
        print(f"Injected vars:    {', '.join(report['injected_env_vars'])}")
    if report["will_prompt_biometric"]:
        print(
            "Biometric prompt: YES "
            f"({', '.join(report['prompt_entries_without_lease'])} — no active lease)"
        )
    else:
        print("Biometric prompt: no")
    if report["command"]:
        cmd_ok = "found" if report["command_executable_found"] else "NOT FOUND"
        print(f"Command:          {' '.join(report['command'])} ({cmd_ok})")
    if report["remediation"]:
        print("\nRemediation:")
        for item in report["remediation"]:
            print(f"  - {item}")


def handle_run_command(parser, args):
    """Handler for the 'run' subcommand."""
    from ..interactive import can_prompt_interactively, select_multiple_entries, set_no_input

    run_args = list(args.args)
    no_masking = bool(getattr(args, "no_masking", False))
    quiet = bool(getattr(args, "quiet", False))
    dry_run = bool(getattr(args, "dry_run", False))
    json_output = bool(getattr(args, "json_output", False))
    strict = bool(getattr(args, "strict", False))
    env_files: list[str] = list(getattr(args, "env_files", None) or [])

    if "--" in run_args:
        sep_idx = run_args.index("--")
        pre_sep = run_args[:sep_idx]
        cmd = run_args[sep_idx + 1 :]
    elif dry_run or "--dry-run" in run_args:
        pre_sep = run_args
        cmd = []
    else:
        parser.error(
            "Usage: passkey run [-q|--quiet] [--strict] [--dry-run [--json]] "
            "[--no-masking] <entries...> -- <command>"
        )

    entries: list[str] = []
    idx = 0
    while idx < len(pre_sep):
        token = pre_sep[idx]
        if token == "--no-masking":
            no_masking = True
        elif token in ("-q", "--quiet"):
            quiet = True
        elif token == "--dry-run":
            dry_run = True
        elif token == "--json":
            json_output = True
        elif token == "--strict":
            strict = True
        elif token == "--no-input":
            set_no_input(True)
        elif token == "--env-file":
            if idx + 1 >= len(pre_sep):
                raise PasskeyError("--env-file requires a path argument")
            env_files.append(pre_sep[idx + 1])
            idx += 2
            continue
        elif token.startswith("--env-file="):
            env_files.append(token.split("=", 1)[1])
        elif token.startswith("-"):
            raise PasskeyError(f"Unknown option '{token}' for 'passkey run'")
        else:
            entries.append(token)
        idx += 1

    if json_output and not dry_run:
        raise PasskeyError(
            "'--json' on 'passkey run' requires '--dry-run' "
            "(child command stdout is never wrapped in JSON)."
        )

    if dry_run:
        from ..interactive import is_json_output_env

        report = runner.preflight_run(entries, cmd or None, env_files=env_files)
        if json_output or is_json_output_env():
            print(json.dumps(report, indent=2))
        else:
            _print_preflight_report(report)
        sys.exit(0 if report["ready"] else 1)

    if not entries and not env_files:
        import os as _os

        from ..references import is_reference

        has_inherited_refs = any(is_reference(v) for v in _os.environ.values())
        if not has_inherited_refs:
            if can_prompt_interactively():
                entries = select_multiple_entries("Select entries to load secrets from")
            else:
                raise PasskeyError(
                    "No entries specified for 'run' in non-interactive mode. "
                    "Usage: passkey run -q <entry> -- <command>"
                )

    if not cmd:
        raise PasskeyError("No command specified after --")

    rc = runner.run_with_secrets(
        entries,
        cmd,
        no_masking=no_masking,
        quiet=quiet,
        strict=strict,
        env_files=env_files,
    )
    sys.exit(rc)


def print_project_status(status: dict) -> None:
    """Render a human-readable summary for ``passkey project status`` / ``exec --dry-run``."""
    if not status.get("manifest_found"):
        print(f"Project root:     {status['project_root']}")
        print("Manifest status:  NOT FOUND")
        if status.get("detected_templates"):
            print(f"Templates found:  {', '.join(status['detected_templates'])}")
        for item in status.get("remediation", []):
            print(f"  -> {item}")
        return

    ready_label = "READY" if status["ready"] else "NOT READY"
    trust_label = "TRUSTED" if status["trusted"] else f"UNTRUSTED ({status['trust_status']})"
    print(f"Project root:     {status['project_root']}")
    print(f"Manifests:        {', '.join(status['manifests'])}")
    print(f"Trust status:     {trust_label}")
    print(f"Readiness:        {ready_label}")
    if status.get("entries"):
        print(f"Entries:          {', '.join(status['entries'])}")
    if status.get("injected_env_vars"):
        print(f"Injected vars:    {', '.join(status['injected_env_vars'])}")
    if status.get("entries_missing"):
        print(f"Entries missing:  {', '.join(status['entries_missing'])}")
    if status.get("missing_required_vars"):
        print(f"Missing required: {', '.join(status['missing_required_vars'])}")
    if status.get("will_prompt_biometric"):
        print("Biometric prompt: YES")
    else:
        print("Biometric prompt: no")
    if status.get("remediation"):
        print("\nRemediation:")
        for item in status["remediation"]:
            print(f"  - {item}")


def handle_exec_command(parser, args):
    """Handler for the zero-config ``passkey exec`` subcommand."""
    from ..interactive import is_json_output_env, set_no_input
    from ..project import exec_with_project

    exec_args = list(args.args)
    no_masking = bool(getattr(args, "no_masking", False))
    quiet = bool(getattr(args, "quiet", False))
    dry_run = bool(getattr(args, "dry_run", False))
    json_output = bool(getattr(args, "json_output", False))
    no_strict = bool(getattr(args, "no_strict", False))
    project_dir = getattr(args, "project_dir", None)

    if "--" in exec_args:
        sep_idx = exec_args.index("--")
        pre_sep = exec_args[:sep_idx]
        cmd = exec_args[sep_idx + 1 :]
    else:
        pre_sep = []
        cmd = []
        idx = 0
        while idx < len(exec_args):
            tok = exec_args[idx]
            if tok in (
                "--no-masking",
                "-q",
                "--quiet",
                "--dry-run",
                "--json",
                "--no-strict",
                "--no-input",
            ):
                pre_sep.append(tok)
                idx += 1
            elif tok == "--project-dir" and idx + 1 < len(exec_args):
                pre_sep.extend([tok, exec_args[idx + 1]])
                idx += 2
            elif tok.startswith("--project-dir="):
                pre_sep.append(tok)
                idx += 1
            elif tok.startswith("-"):
                raise PasskeyError(
                    f"Unknown option '{tok}' for 'passkey exec'. "
                    "Place '--' before command arguments: passkey exec -- <command>",
                    error_code="INVALID_USAGE",
                    remediation_command="passkey exec -- <command>",
                )
            else:
                cmd = exec_args[idx:]
                break

    idx = 0
    while idx < len(pre_sep):
        token = pre_sep[idx]
        if token == "--no-masking":
            no_masking = True
        elif token in ("-q", "--quiet"):
            quiet = True
        elif token == "--dry-run":
            dry_run = True
        elif token == "--json":
            json_output = True
        elif token == "--no-strict":
            no_strict = True
        elif token == "--no-input":
            set_no_input(True)
        elif token == "--project-dir":
            if idx + 1 >= len(pre_sep):
                raise PasskeyError(
                    "--project-dir requires a path argument",
                    error_code="INVALID_USAGE",
                )
            project_dir = pre_sep[idx + 1]
            idx += 2
            continue
        elif token.startswith("--project-dir="):
            project_dir = token.split("=", 1)[1]
        else:
            raise PasskeyError(
                f"Unexpected argument '{token}' before '--' in 'passkey exec'. "
                "Usage: passkey exec [-q] [--dry-run [--json]] -- <command>",
                error_code="INVALID_USAGE",
                remediation_command="passkey exec -- <command>",
            )
        idx += 1

    if json_output and not dry_run:
        raise PasskeyError(
            "'--json' on 'passkey exec' requires '--dry-run' "
            "(child command stdout is never wrapped in JSON).",
            error_code="INVALID_USAGE",
        )

    result = exec_with_project(
        cmd or None,
        project_dir=project_dir,
        quiet=quiet,
        no_masking=no_masking,
        dry_run=dry_run,
        strict=not no_strict,
    )

    if dry_run:
        assert isinstance(result, dict)
        if json_output or is_json_output_env():
            print(json.dumps(result, indent=2))
        else:
            print_project_status(result)
        sys.exit(0 if (result["ready"] and result["trusted"]) else 1)

    assert isinstance(result, int)
    sys.exit(result)


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
        from ..interactive import require_interactive

        human_cmd = f"passkey entry template apply {args.template_name}"
        if args.entry_name:
            human_cmd += f" {args.entry_name}"
        require_interactive("passkey template apply", human_command=human_cmd)
        _require_auth("create entries from template")
        template = get_template(args.template_name)
        if not template:
            raise PasskeyError(f"Template '{args.template_name}' not found")
        entry_name = args.entry_name or template["name"]
        commands.cmd_template_apply(template, entry_name)

    elif args.template_command == "add":
        from ..interactive import require_interactive

        require_interactive(
            "passkey template add",
            human_command="passkey entry template add",
        )
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
    from ..interactive import (
        PASSKEY_STYLE,
        InteractiveRequiredError,
        can_prompt_interactively,
    )
    from ..keychain import list_entries

    try:
        entries = list_entries()
    except PasskeyError:
        entries = []

    if not can_prompt_interactively():
        exposed = mcp_commands.detect_exposed_mcp_servers()
        human_cmd = "passkey init" if exposed else "passkey new <name>"
        alt = (
            "passkey list --json | passkey info <entry> --json | "
            "passkey status --json | passkey doctor --json | "
            "passkey run -q <entry> -- <command>"
        )
        summary = f"{len(entries)} entry(s) in keychain"
        if exposed:
            summary += f", {len(exposed)} MCP server(s) with plaintext secrets"
        raise InteractiveRequiredError(
            f"Bare 'passkey' launches an interactive TUI ({summary}) and cannot run headlessly.\n"
            f"  Headless commands: {alt}\n"
            f"  Ask the user to run in their terminal: {human_cmd}\n"
            "  Security rule: Never ask the user to paste secret values into chat.",
            error_code="INTERACTIVE_REQUIRED",
            remediation_command="passkey list --json",
        )

    # State C: Entries already exist -> fuzzy entry browser on TTY
    if entries:
        _require_auth = _get_require_auth()
        _require_auth("access secrets")
        entry = resolve_entry(None, "Select entry to browse")
        commands.cmd_get_interactive(entry)
        return

    # 0 entries: check for exposed MCP configs on disk
    exposed = mcp_commands.detect_exposed_mcp_servers()

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
            "How would you like to get started?",
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
