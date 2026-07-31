"""Argument parser for passkey CLI."""

import argparse

from .. import __version__

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
        "init", "unwrap", "status", "doctor", "servers", "add",
    ]),
    ("Utilities", [
        "config", "completion", "mcp-serve",
    ]),
]


def _entry_completer(**kwargs):
    """Return entry names for shell tab completion. Silent on any error."""
    try:
        from ..keychain import list_entries

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
    list_parser = subparsers.add_parser("list", help="List all entries")
    list_parser.add_argument(
        "-n", "--names-only", action="store_true", help="Print only names, one per line"
    )

    # get
    get_parser = subparsers.add_parser("get", help="Browse and copy fields")
    get_parser.add_argument("entry", help="Entry name")
    get_parser.add_argument(
        "--all",
        "-a",
        dest="get_all",
        action="store_true",
        help="Copy all fields to clipboard instead of interactive picker",
    )
    get_parser.completer = _entry_completer

    # edit
    edit_parser = subparsers.add_parser("edit", help="Edit an existing entry")
    edit_parser.add_argument("entry", help="Entry name")
    edit_parser.completer = _entry_completer

    # delete
    delete_parser = subparsers.add_parser("delete", help="Delete an entry")
    delete_parser.add_argument("entry", help="Entry name")
    delete_parser.completer = _entry_completer

    # info
    info_parser = subparsers.add_parser("info", help="Show entry details")
    info_parser.add_argument("entry", help="Entry name")
    info_parser.completer = _entry_completer

    # clone
    clone_parser = subparsers.add_parser("clone", help="Clone an entry")
    clone_parser.add_argument("source", help="Source entry name")
    clone_parser.add_argument("dest", help="Destination entry name")
    clone_parser.add_argument(
        "--fields", nargs="+", help="Specific fields to clone (default: all)"
    )
    clone_parser.completer = _entry_completer

    # set-field
    set_field_parser = subparsers.add_parser("set-field", help="Add or update a field")
    set_field_parser.add_argument("entry", help="Entry name")
    set_field_parser.add_argument("field", help="Field name")
    set_field_parser.add_argument("value", nargs="?", help="Field value (prompts if omitted)")
    set_field_parser.completer = _entry_completer

    # check
    check_parser = subparsers.add_parser("check", help="Verify required fields exist")
    check_parser.add_argument("entry", help="Entry name")
    check_parser.add_argument("fields", nargs="+", help="Required field names")
    check_parser.add_argument(
        "-q", "--quiet", action="store_true", help="Only exit non-zero if fields missing"
    )
    check_parser.completer = _entry_completer

    # generate
    generate_parser = subparsers.add_parser("generate", help="Generate a random secret")
    generate_parser.add_argument(
        "--length", type=int, default=32, help="Length in characters (default: 32)"
    )
    generate_parser.add_argument(
        "--no-copy", action="store_true", help="Print to stdout instead of copying"
    )

    # run
    run_parser = subparsers.add_parser("run", help="Run command with secrets as env vars")
    run_parser.add_argument("args", nargs=argparse.REMAINDER, help="entries... -- command")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Show recent secret access history")
    audit_parser.add_argument(
        "--limit", type=int, default=10, help="Number of entries to show (default: 10)"
    )
    audit_parser.add_argument(
        "--clear", action="store_true", help="Clear the audit log"
    )
    audit_parser.add_argument(
        "--summary", action="store_true", help="Show 30-day summary by entry"
    )

    # rotate
    rotate_parser = subparsers.add_parser("rotate", help="Rotate a secret")
    rotate_parser.add_argument("entry", help="Entry name")
    rotate_parser.add_argument("field", nargs="?", help="Field name (prompts if omitted)")
    rotate_parser.completer = _entry_completer

    # template
    template_parser = subparsers.add_parser("template", help="Template management")
    template_sub = template_parser.add_subparsers(dest="template_command")
    template_sub.add_parser("list", help="List available templates")
    template_sub.add_parser("show", help="Show template details").add_argument(
        "template_name", help="Template name"
    )
    template_apply = template_sub.add_parser("apply", help="Apply a template to create an entry")
    template_apply.add_argument("template_name", help="Template name")
    template_apply.add_argument("entry_name", nargs="?", help="Entry name (defaults to template name)")
    template_sub.add_parser("add", help="Save an existing entry as a custom template")

    # export
    export_parser = subparsers.add_parser("export", help="Export entries")
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
    export_parser.completer = _entry_completer

    # import
    import_parser = subparsers.add_parser("import", help="Import entries")
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

    # share
    share_parser = subparsers.add_parser("share", help="Share an entry via encrypted bundle")
    share_parser.add_argument("entry", help="Entry name")
    share_parser.add_argument("--output", "-o", help="Output file path")
    share_parser.add_argument("--shared-by", help="Identifier for the sharer")
    share_parser.completer = _entry_completer

    # receive
    receive_parser = subparsers.add_parser("receive", help="Receive a shared bundle")
    receive_parser.add_argument("file", help="Bundle file path")

    # unwrap
    unwrap_parser = subparsers.add_parser("unwrap", help="Restore wrapped MCP config to inline commands")
    unwrap_parser.add_argument("--tool", help="Tool name (e.g., claude, vscode)")
    unwrap_parser.add_argument("--server", help="Server name to unwrap")
    unwrap_parser.add_argument("--config", help="Config file path")
    unwrap_parser.add_argument(
        "--restore-secrets",
        action="store_true",
        help="Also write secret values back into the config file",
    )
    unwrap_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be changed without changing it"
    )

    # config
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_parser.add_argument("key", nargs="?", help="Setting name")
    config_parser.add_argument("value", nargs="?", help="New value")

    # init
    init_parser = subparsers.add_parser("init", help="Migrate MCP config secrets to keychain")
    init_parser.add_argument("--tool", help="Tool name (e.g., claude, vscode)")
    init_parser.add_argument("--config", help="Config file path")
    init_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be migrated without migrating"
    )
    init_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing entries for the same servers"
    )
    init_parser.add_argument(
        "--include-all",
        action="store_true",
        help="Include all env vars (not just detected secrets)",
    )
    init_parser.add_argument("--backup", help="Custom backup file path")

    # status
    status_parser = subparsers.add_parser("status", help="Show MCP server security status")
    status_parser.add_argument("--tool", help="Tool name")
    status_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output as JSON"
    )

    # servers
    servers_parser = subparsers.add_parser("servers", help="List MCP servers across tools")
    servers_parser.add_argument("--tool", help="Tool name")
    servers_parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output as JSON"
    )

    # add
    add_parser = subparsers.add_parser("add", help="Add credentials for an MCP server")
    add_parser.add_argument("server", help="Server name")
    add_parser.add_argument("--tool", help="Tool name")
    add_parser.add_argument(
        "--fields", nargs="+", help="Field names to add (prompts for values)"
    )

    # doctor
    doctor_parser = subparsers.add_parser("doctor", help="Run diagnostics")
    doctor_parser.add_argument(
        "--deep", action="store_true", help="Run extended diagnostics including network checks"
    )

    # completion
    completion_parser = subparsers.add_parser("completion", help="Print shell tab completion scripts")
    completion_parser.add_argument("--bash", action="store_true", help="Print bash completion script")
    completion_parser.add_argument("--zsh", action="store_true", help="Print zsh completion script")
    completion_parser.add_argument("--fish", action="store_true", help="Print fish completion script")

    # mcp-serve
    subparsers.add_parser("mcp-serve", help="Start the MCP server (usually called internally)")

    return parser
