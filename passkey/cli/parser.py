"""Argument parser for passkey CLI."""

import argparse
from importlib.metadata import version as package_version

SUBPARSER_GROUPS: list[tuple[str, list[str]]] = [
    (
        "Core Secret Management",
        ["new", "get", "list", "edit", "delete", "info", "entry"],
    ),
    (
        "Run & Inject",
        ["run", "inject", "mount", "plugin", "browser-fill"],
    ),
    (
        "MCP & AI Guardrails",
        ["init", "status", "doctor", "mcp", "hook", "audit", "policy", "lease"],
    ),
    (
        "Portability & Config",
        ["export", "import", "share", "receive", "config", "completion"],
    ),
]

EXAMPLES_EPILOG = """\
Examples:
  passkey new stripe                        Create 'stripe' and paste secrets safely
  passkey stripe                            Fuzzy-find and copy fields from 'stripe'
  passkey run stripe -- python app.py       Run a command with secrets as env vars
  passkey init                              Migrate plaintext MCP secrets to keychain
  passkey mcp status                        Audit MCP server security across tools
  passkey inject -i .env.tpl -o .env        Render passkey:// placeholders into file
  passkey export backup.passkey --encrypt   Save an encrypted backup bundle

Learn more:
  Run 'passkey <command> --help' for flags and usage of any command.
"""


class GroupedArgumentParser(argparse.ArgumentParser):
    """Top-level parser rendering categorized gh-style --help sections."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._command_summaries: dict[str, str] = {}

    def register_command_summary(self, name: str, summary: str) -> None:
        """Record a one-line description for categorized top-level --help."""
        self._command_summaries[name] = summary

    def format_help(self) -> str:
        lines: list[str] = [
            f"usage: {self.prog} <command> [options]",
            "",
            self.description or "",
            "",
        ]

        col_w = 14
        for group_title, cmd_names in SUBPARSER_GROUPS:
            lines.append(f"{group_title}:")
            for cmd in cmd_names:
                desc = self._command_summaries.get(cmd, "")
                lines.append(f"  {cmd:<{col_w}}{desc}")
            lines.append("")

        lines.extend(
            [
                "Flags:",
                f"  {'-h, --help':<{col_w}}Show this help message and exit",
                f"  {'--version':<{col_w}}Show program's version number and exit",
                "",
                EXAMPLES_EPILOG.rstrip(),
                "",
            ]
        )
        return "\n".join(lines)


def _entry_completer(**kwargs):
    """Return entry names for shell tab completion. Silent on any error."""
    try:
        from ..keychain import list_entries

        return list_entries()
    except Exception:
        return []


def _configure_new_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("name", nargs="?", help="Optional entry name (e.g., stripe)")
    p.add_argument(
        "-t",
        "--template",
        dest="template",
        help="Populate fields from a template (e.g., github, aws, stripe)",
    )
    return p


def _configure_list_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument(
        "-n", "--names-only", action="store_true", help="Print only names, one per line"
    )
    return p


def _configure_get_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("entry", nargs="?", help="Entry name (opens fuzzy selector if omitted)")
    p.add_argument(
        "--all",
        "-a",
        dest="get_all",
        action="store_true",
        help="Copy all fields as KEY='value' env lines instead of interactive picker",
    )
    p.completer = _entry_completer  # type: ignore[attr-defined]
    return p


def _configure_edit_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("entry", nargs="?", help="Entry name")
    p.completer = _entry_completer  # type: ignore[attr-defined]
    return p


def _configure_delete_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("entry", help="Entry name")
    p.completer = _entry_completer  # type: ignore[attr-defined]
    return p


def _configure_info_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("entry", nargs="?", help="Entry name")
    p.completer = _entry_completer  # type: ignore[attr-defined]
    return p


def _configure_clone_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("source", help="Source entry name")
    p.add_argument("dest", nargs="?", help="Destination entry name")
    p.add_argument("--fields", nargs="+", help="Specific fields to clone (default: all)")
    p.completer = _entry_completer  # type: ignore[attr-defined]
    return p


def _configure_set_field_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("entry", help="Entry name")
    p.add_argument("field", help="Field name (prompts securely for value)")
    p.completer = _entry_completer  # type: ignore[attr-defined]
    return p


def _configure_check_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("entry", help="Entry name")
    p.add_argument("fields", nargs="+", help="Required field names")
    p.add_argument(
        "-q", "--quiet", action="store_true", help="Only exit non-zero if fields missing"
    )
    p.completer = _entry_completer  # type: ignore[attr-defined]
    return p


def _configure_generate_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument(
        "--length", type=int, default=32, help="Length in characters (default: 32)"
    )
    p.add_argument(
        "--no-copy", action="store_true", help="Print to stdout instead of copying"
    )
    return p


def _configure_rotate_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("entry", help="Entry name")
    p.add_argument("field", nargs="?", help="Field name (prompts if omitted)")
    p.completer = _entry_completer  # type: ignore[attr-defined]
    return p


def _configure_template_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    template_sub = p.add_subparsers(dest="template_command")
    template_sub.add_parser("list", help="List available templates")
    template_sub.add_parser("show", help="Show template details").add_argument(
        "template_name", help="Template name"
    )
    template_apply = template_sub.add_parser("apply", help="Apply a template to create an entry")
    template_apply.add_argument("template_name", help="Template name")
    template_apply.add_argument(
        "entry_name", nargs="?", help="Entry name (defaults to template name)"
    )
    template_sub.add_parser("add", help="Save an existing entry as a custom template")
    return p


def _configure_init_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("--tool", help="Tool name (e.g., claude, vscode)")
    p.add_argument("--config", help="Config file path")
    p.add_argument(
        "--dry-run", action="store_true", help="Show what would be migrated without migrating"
    )
    p.add_argument(
        "--force", action="store_true", help="Overwrite existing entries for the same servers"
    )
    p.add_argument(
        "--include-all",
        action="store_true",
        help="Include all env vars (not just detected secrets)",
    )
    p.add_argument("--backup", help="Custom backup file path")
    return p


def _configure_status_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("--tool", help="Tool name")
    p.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    return p


def _configure_servers_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("--tool", help="Tool name")
    p.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    return p


def _configure_add_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("server", help="Server name")
    p.add_argument("--tool", help="Tool name")
    p.add_argument("--fields", nargs="+", help="Field names to add (prompts for values)")
    return p


def _configure_unwrap_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument("--tool", help="Tool name (e.g., claude, vscode)")
    p.add_argument("--server", help="Server name to unwrap")
    p.add_argument("--config", help="Config file path")
    p.add_argument(
        "--restore-secrets",
        action="store_true",
        help="Also write secret values back into the config file",
    )
    p.add_argument(
        "--dry-run", action="store_true", help="Show what would be changed without changing it"
    )
    return p


def _configure_doctor_parser(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
    p.add_argument(
        "--deep", action="store_true", help="Run extended diagnostics including audit checks"
    )
    return p


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = GroupedArgumentParser(
        prog="passkey",
        usage="%(prog)s <command> [options]",
        description="Local OS-keychain secret manager and injector for CLIs & MCP servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {package_version('passkey-mcp')}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="<command>",
        parser_class=argparse.ArgumentParser,
    )

    def _add_primary(name: str, summary: str, **kwargs) -> argparse.ArgumentParser:
        parser.register_command_summary(name, summary)
        return subparsers.add_parser(name, help=summary, description=summary, **kwargs)

    # ── Core Secret Management ────────────────────────────────────────────
    _configure_new_parser(_add_primary("new", "Create a new secret entry"))
    _configure_get_parser(_add_primary("get", "Browse and copy fields from an entry"))
    _configure_list_parser(_add_primary("list", "List all saved entries"))
    _configure_edit_parser(_add_primary("edit", "Interactive editor for an existing entry"))
    _configure_delete_parser(_add_primary("delete", "Delete an entry from the keychain"))
    _configure_info_parser(_add_primary("info", "Show entry metadata and field names"))

    # Noun-verb group: passkey entry <subcommand>
    entry_group = _add_primary(
        "entry",
        "Advanced entry subcommands (run 'passkey entry --help')",
    )
    entry_sub = entry_group.add_subparsers(dest="entry_command", metavar="<subcommand>")
    _configure_clone_parser(entry_sub.add_parser("clone", help="Clone an entry"))
    _configure_set_field_parser(
        entry_sub.add_parser("set-field", help="Add or update a single field")
    )
    _configure_rotate_parser(
        entry_sub.add_parser("rotate", help="Rotate a secret field and timestamp")
    )
    _configure_check_parser(
        entry_sub.add_parser("check", help="Verify required fields exist on an entry")
    )
    _configure_template_parser(
        entry_sub.add_parser("template", help="List, show, apply, or save entry templates")
    )
    _configure_generate_parser(
        entry_sub.add_parser("generate", help="Generate a cryptographically random secret")
    )
    _configure_new_parser(entry_sub.add_parser("new", help="Create a new secret entry"))
    _configure_get_parser(entry_sub.add_parser("get", help="Browse and copy fields"))
    _configure_list_parser(entry_sub.add_parser("list", help="List all entries"))
    _configure_edit_parser(entry_sub.add_parser("edit", help="Edit an existing entry"))
    _configure_delete_parser(entry_sub.add_parser("delete", help="Delete an entry"))
    _configure_info_parser(entry_sub.add_parser("info", help="Show entry details"))

    # ── Run & Inject ──────────────────────────────────────────────────────
    run_parser = _add_primary("run", "Run a command with secrets injected as env vars")
    run_parser.add_argument(
        "--no-masking",
        action="store_true",
        help="Disable masking of secret values on child stdout and stderr",
    )
    run_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress passkey warning and status output on stderr",
    )
    run_parser.add_argument(
        "--env-file",
        action="append",
        default=[],
        dest="env_files",
        help="Load KEY=VALUE / passkey:// references from file (repeatable)",
    )
    run_parser.add_argument("args", nargs=argparse.REMAINDER, help="entries... -- command")

    inject_parser = _add_primary(
        "inject", "Render {{ passkey://entry/field }} placeholders into a file"
    )
    inject_parser.add_argument("-i", "--in-file", required=True, help="Input template file")
    inject_parser.add_argument("-o", "--out-file", help="Output file path (0600 atomic write)")
    inject_parser.add_argument(
        "--stdout",
        action="store_true",
        help="Write rendered output to stdout (interactive TTY required)",
    )
    inject_parser.add_argument(
        "-f", "--force", action="store_true", help="Overwrite output file if it already exists"
    )

    mount_parser = _add_primary(
        "mount", "Stream secrets via an ephemeral POSIX FIFO (.env)"
    )
    mount_parser.add_argument("entries", nargs="+", help="Entry names to expose via FIFO")
    mount_parser.add_argument(
        "--path", default=".env", help="FIFO file path to create (default: .env)"
    )
    mount_parser.add_argument(
        "--once", action="store_true", help="Exit automatically after serving one reader"
    )
    mount_parser.add_argument(
        "--max-reads", type=int, help="Exit after serving N readers (default: unlimited)"
    )
    mount_parser.add_argument(
        "--force-git-exposed",
        action="store_true",
        help="Allow mounting even if target path is not gitignored",
    )
    mount_parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress status output on stderr"
    )

    plugin_parser = _add_primary(
        "plugin", "Zero-config secret wrappers for AI and cloud CLIs"
    )
    plugin_sub = plugin_parser.add_subparsers(dest="plugin_command")
    plugin_sub.add_parser("list", help="List supported CLI plugins and active bindings")
    plugin_init = plugin_sub.add_parser("init", help="Bind a CLI plugin to a passkey entry")
    plugin_init.add_argument("cli", help="CLI executable name (e.g., claude, gh, aws)")
    plugin_init.add_argument("--entry", help="Passkey entry name (defaults to CLI template name)")
    plugin_init.add_argument(
        "--scope",
        choices=["session", "dir", "global"],
        default="global",
        help="Binding scope: session (shell snippet), dir (.passkey.toml), or global (default)",
    )
    plugin_run = plugin_sub.add_parser("run", help="Run a CLI plugin with masked secret injection")
    plugin_run.add_argument("cli", help="CLI executable name")
    plugin_run.add_argument("--entry", help="Explicit passkey entry override")
    plugin_run.add_argument(
        "--no-masking", action="store_true", help="Disable stdout/stderr secret masking"
    )
    plugin_run.add_argument("args", nargs=argparse.REMAINDER, help="-- <cli arguments>")

    bf_parser = _add_primary(
        "browser-fill", "Fill credentials into a local CDP browser tab"
    )
    bf_parser.add_argument("entry", help="Passkey entry containing ORIGIN and credentials")
    bf_parser.add_argument(
        "--cdp-url",
        required=True,
        help="Loopback Chrome DevTools WebSocket URL (e.g., ws://127.0.0.1:9222)",
    )
    bf_parser.completer = _entry_completer  # type: ignore[attr-defined]

    # ── MCP & AI Guardrails ───────────────────────────────────────────────
    _configure_init_parser(
        _add_primary("init", "Migrate plaintext MCP config secrets to keychain")
    )
    _configure_status_parser(
        _add_primary("status", "Show MCP server security status across tools")
    )
    _configure_doctor_parser(
        _add_primary("doctor", "Run keychain and MCP configuration diagnostics")
    )

    # Noun-verb group: passkey mcp <subcommand>
    mcp_group = _add_primary(
        "mcp", "MCP server management subcommands (run 'passkey mcp --help')"
    )
    mcp_sub = mcp_group.add_subparsers(dest="mcp_command", metavar="<subcommand>")
    _configure_init_parser(
        mcp_sub.add_parser("init", help="Migrate MCP config secrets to keychain")
    )
    _configure_status_parser(
        mcp_sub.add_parser("status", help="Show MCP server security status")
    )
    _configure_servers_parser(
        mcp_sub.add_parser("servers", help="List MCP servers across tools")
    )
    _configure_add_parser(
        mcp_sub.add_parser("add", help="Add credentials for an MCP server")
    )
    _configure_unwrap_parser(
        mcp_sub.add_parser("unwrap", help="Restore wrapped MCP config to inline commands")
    )
    _configure_doctor_parser(
        mcp_sub.add_parser("doctor", help="Run MCP and keychain diagnostics")
    )

    hook_parser = _add_primary(
        "hook", "Install pre-execution secret-protection hooks for AI agents"
    )
    hook_sub = hook_parser.add_subparsers(dest="hook_command")
    hook_install = hook_sub.add_parser(
        "install", help="Install non-destructive pre-tool guard hook for an AI tool"
    )
    hook_install.add_argument(
        "--tool",
        required=True,
        choices=["claude", "cursor", "gemini"],
        help="Target AI coding tool",
    )
    hook_install.add_argument(
        "--project-dir", help="Project directory (default: current working directory)"
    )
    hook_check = hook_sub.add_parser("check", help="Evaluate hook payload from stdin")
    hook_check.add_argument(
        "--tool",
        choices=["claude", "cursor", "gemini"],
        help="Hook caller format",
    )

    audit_parser = _add_primary(
        "audit", "View or verify tamper-evident secret access history"
    )
    audit_parser.add_argument(
        "--limit", type=int, default=10, help="Number of entries to show (default: 10)"
    )
    audit_parser.add_argument("--clear", action="store_true", help="Clear the audit log")
    audit_parser.add_argument(
        "--summary", action="store_true", help="Show 30-day summary by entry"
    )
    audit_parser.add_argument(
        "--verify", action="store_true", help="Verify HMAC-SHA256 hash chain integrity"
    )

    policy_parser = _add_primary(
        "policy", "Show or set an entry's access policy (allow or prompt)"
    )
    policy_parser.add_argument("entry", help="Entry name")
    policy_parser.add_argument(
        "policy_value",
        nargs="?",
        choices=["allow", "prompt"],
        help="Access policy: 'allow' (headless) or 'prompt' (requires Touch ID / lease)",
    )
    policy_parser.completer = _entry_completer  # type: ignore[attr-defined]

    lease_parser = _add_primary(
        "lease", "Grant or revoke temporary leases for prompt-gated entries"
    )
    lease_sub = lease_parser.add_subparsers(dest="lease_command")
    lease_grant = lease_sub.add_parser("grant", help="Grant a temporary lease for an entry")
    lease_grant.add_argument("entry", help="Entry name")
    lease_grant.add_argument(
        "--ttl", default="15m", help="Lease duration (e.g., 15m, 30s, 1h; default: 15m)"
    )
    lease_grant.add_argument(
        "--max-uses", type=int, help="Maximum number of injections before automatic expiry"
    )
    lease_sub.add_parser("list", help="List active leases")
    lease_revoke = lease_sub.add_parser("revoke", help="Revoke one or all active leases")
    lease_revoke.add_argument("entry", nargs="?", help="Entry name to revoke")
    lease_revoke.add_argument(
        "--all", action="store_true", dest="revoke_all", help="Revoke all leases"
    )

    # ── Portability & Config ──────────────────────────────────────────────
    export_parser = _add_primary("export", "Export entries to JSON or an encrypted bundle")
    export_parser.add_argument("file", help="Output file path")
    export_parser.add_argument(
        "--entries", nargs="+", help="Specific entries to export (default: all)"
    )
    export_parser.add_argument(
        "--no-secrets", action="store_true", help="Export field names only, no values"
    )
    export_parser.add_argument(
        "--encrypt", action="store_true", help="Encrypt the export bundle"
    )
    export_parser.completer = _entry_completer  # type: ignore[attr-defined]

    import_parser = _add_primary(
        "import", "Import entries from JSON, CSV, Chrome, or bundle"
    )
    import_parser.add_argument("file", help="Input file path")
    import_parser.add_argument(
        "--mode",
        choices=["auto", "passkey", "csv", "chrome"],
        default="auto",
        help="Import format (default: auto-detect)",
    )
    import_parser.add_argument(
        "--decrypt", action="store_true", help="Decrypt an encrypted bundle before importing"
    )
    import_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be imported without importing"
    )
    import_parser.add_argument(
        "--filter", help="Only import entries matching this domain/name prefix"
    )
    import_parser.add_argument(
        "--insecure", action="store_true", help="Allow importing plaintext CSV files"
    )

    share_parser = _add_primary("share", "Share a single entry via an encrypted bundle")
    share_parser.add_argument("entry", help="Entry name")
    share_parser.add_argument("--output", "-o", help="Output file path")
    share_parser.add_argument("--shared-by", help="Identifier for the sharer")
    share_parser.completer = _entry_completer  # type: ignore[attr-defined]

    receive_parser = _add_primary("receive", "Import a shared entry bundle")
    receive_parser.add_argument("file", help="Bundle file path")

    config_parser = _add_primary("config", "View or update passkey settings")
    config_parser.add_argument("key", nargs="?", help="Setting name")
    config_parser.add_argument("value", nargs="?", help="New value")

    completion_parser = _add_primary(
        "completion", "Print shell tab-completion scripts (bash, zsh, fish)"
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

    # ── Backwards-Compatible Top-Level Aliases & Plumbing (hidden in top --help) ──
    _configure_clone_parser(subparsers.add_parser("clone"))
    _configure_set_field_parser(subparsers.add_parser("set-field"))
    _configure_check_parser(subparsers.add_parser("check"))
    _configure_generate_parser(subparsers.add_parser("generate"))
    _configure_rotate_parser(subparsers.add_parser("rotate"))
    _configure_template_parser(subparsers.add_parser("template"))
    _configure_unwrap_parser(subparsers.add_parser("unwrap"))
    _configure_servers_parser(subparsers.add_parser("servers"))
    _configure_add_parser(subparsers.add_parser("add"))
    subparsers.add_parser("mcp-serve", description="Start the passkey FastMCP server.")

    # Expose subcommand groups for empty-group help rendering
    parser._mcp_group_parser = mcp_group  # type: ignore[attr-defined]
    parser._entry_group_parser = entry_group  # type: ignore[attr-defined]

    return parser
