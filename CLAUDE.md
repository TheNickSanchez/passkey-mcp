# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Passkey is a cross-platform Python CLI utility for managing secrets in the system keychain with Claude MCP integration. It stores named "entries" (like `github`, `slack`) where each entry contains multiple key-value pairs that can be injected as environment variables.

**Status**: Implemented and functional.

## Architecture

Secrets are stored as JSON in system keychain items:
- Service name: `passkey`
- Account: `<entry_name>` (e.g., "github")
- Password: JSON object of fields (e.g., `{"GITHUB_TOKEN": "..."}`)

Entry names are tracked in a metadata key (`__entries__`) for listing.

### Module Structure

| Module | Responsibility |
|--------|----------------|
| `models.py` | `Entry` dataclass with JSON serialization |
| `keychain.py` | CRUD operations via `keyring` library |
| `dirs.py` | Cross-platform data directory resolution |
| `cli.py` | argparse-based CLI entry point |
| `commands.py` | CLI command handlers |
| `runner.py` | Environment variable injection for subprocess execution |
| `clipboard.py` | Clipboard operations via `pyperclip` |
| `interactive.py` | Interactive CLI with fuzzy search (questionary) |
| `claude.py` | Claude config file manipulation and security analysis |
| `claude_commands.py` | CLI commands for Claude integration (`passkey claude ...`) |
| `mcp_server.py` | MCP server exposing passkey tools to Claude |
| `importers.py` | Import from Chrome, MCP configs, passkey exports |
| `audit.py` | Audit logging of all operations |

## Build Commands

```bash
# Install dependencies
pip install -e .

# Run CLI (development)
python -m passkey

# Start MCP server (for Claude integration)
passkey mcp-serve
# Or directly:
passkey-mcp-server

# Run tests
pytest tests/ -v
```

## CLI Commands

All commands support interactive mode with fuzzy search when entry name is omitted:

```bash
passkey new                         # Interactive: add entry with fields
passkey list                        # List all entry names
passkey info [entry]                # Show metadata and field names
passkey get [entry]                 # Select a field to copy (interactive picker)
passkey get [entry] --all           # Copy all fields to clipboard
passkey delete [entry]              # Delete entry (exact match required)
passkey edit [entry]                # Edit entry (interactive picker if omitted)
passkey run <entries...> -- <cmd>   # Run command with env vars from entries
passkey <entry>                     # Fuzzy-match shortcut: browse entry directly

# Fuzzy matching examples:
passkey get myapi_                  # Matches myapi_read, myapi_write
passkey info gh                     # Matches github
```

## MCP Integration

### Wrapping MCP Servers

Passkey wraps MCP server commands to inject secrets from the system keychain:

```json
{
  "mcpServers": {
    "github": {
      "command": "passkey",
      "args": ["run", "github", "--", "python", "-m", "github.server"]
    }
  }
}
```

### MCP Server Mode

Passkey can also run as an MCP server itself, exposing tools for Claude to invoke directly.

```json
{
  "mcpServers": {
    "passkey": {
      "command": "passkey-mcp-server"
    }
  }
}
```

## Security Considerations

- Use `getpass.getpass()` for hidden secret input
- Only log entry/field names, never secret values
- Clipboard auto-clears after 30-second timeout
- Requires system keychain access permissions for Python
- On Linux headless environments, set `PYTHON_KEYRING_BACKEND` as directed by error messages
