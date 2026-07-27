# Passkey

A cross-platform secrets manager for AI coding assistants and CLI tools — stores named credential sets in your system keychain and injects them as environment variables at runtime.

No plaintext secrets in config files. No cloud sync. Touch ID / system auth protected.

## Features

- Store multiple secrets per entry in the system keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service)
- Inject secrets as environment variables for subprocesses
- **Tool-agnostic** — works with Claude, Gemini, VS Code, Cursor, OpenCode, Windsurf, Cline, Zed, and more
- Interactive fuzzy-search entry picker (arrow keys + type-to-filter)
- **Tab completion** for bash, zsh, and fish
- Import from Chrome password exports, existing MCP configs, or passkey backups
- Encrypted bundle export/import for safe machine-to-machine transfer
- Full audit logging of all operations
- **Touch ID** / system auth protection (honors your sudo PAM config)
- Cross-platform: macOS, Linux, Windows

## Installation

```bash
# Recommended: install globally with pipx
pipx install passkey-mcp

# Or with pip
pip install passkey-mcp

# Development mode (from source)
pip install -e .
```

### Requirements

- Python 3.10+
- System keychain access (macOS Keychain, Windows Credential Manager, or a running Linux keyring daemon)

## Quick Start

```bash
# First run — guided onboarding
passkey
#  ┌─────────────────────────────────────────────┐
#  │           Welcome to passkey                 │
#  │  Secrets in your keychain. Not in config.    │
#  └─────────────────────────────────────────────┘
#  Create your first entry now? [Y/n]

# Create an entry
passkey new
# Entry name: github
# Field name: GITHUB_TOKEN
# Value: [hidden input]

# List all entries
passkey list

# Run a command with secrets injected
passkey run github -- python app.py
```

## Shell Completion

Set up tab completion for your shell:

```bash
# Zsh (macOS default)
eval "$(passkey completion --zsh)"

# Bash
eval "$(passkey completion --bash)"

# Fish
passkey completion --fish > ~/.config/fish/completions/passkey.fish
```

After setup, tab completion works everywhere:

```bash
passkey <TAB>         # Show entries + subcommands
passkey hugg<TAB>     # Fuzzy-match: huggingface_key
passkey get <TAB>     # Complete entry names
passkey run <TAB>     # Pick entries to load
```

## Interactive Mode

When you omit an entry name (or type a partial match), passkey shows an interactive picker with fuzzy search:

```bash
$ passkey get
? Select entry to browse: (Use arrow keys, type to filter)
❯ github
  openai
  slack
  myapi_read
  myapi_write

# Type to filter:
$ passkey get my
# Automatically shows: myapi_read, myapi_write

# Single match auto-selects:
$ passkey get github
Copied 'GITHUB_TOKEN' to clipboard (auto-clears in 30s)

# Shortcut: passkey <entry> opens the picker directly
$ passkey github
```

### Fuzzy Matching

- **Prefix**: `my` matches `myapi_read`, `myapi_write`
- **Contains**: `api` matches `myapi_read`, `myapi_write`
- **Sequence**: `gh` matches `github`
- **Case-insensitive**: `GITHUB` matches `github`

## CLI Reference

### Entry Management

| Command | Description |
|---------|-------------|
| `passkey new` | Create a new entry interactively |
| `passkey list` | List all entry names |
| `passkey list --names-only` | Entry names only (one per line, for scripting) |
| `passkey edit [entry]` | Modify an existing entry |
| `passkey delete [entry]` | Delete an entry (exact match required) |
| `passkey info [entry]` | Show entry metadata and field names |
| `passkey clone SOURCE [DEST]` | Clone an entry under a new name |
| `passkey set-field ENTRY FIELD [VALUE]` | Upsert a single field |

### Retrieving Secrets

| Command | Description |
|---------|-------------|
| `passkey get [entry]` | Interactive field picker — select a field to copy |
| `passkey get [entry] --all` | Copy all fields to clipboard |
| `passkey <entry>` | Shortcut: same as `passkey get <entry>` |

### Running Commands

```bash
# Run with secrets from one entry
passkey run github -- python app.py

# Run with secrets from multiple entries (later entries override)
passkey run aws github -- python deploy.py

# Secrets injected as env vars
passkey run myapi -- curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/v1/data
```

### Tool Integration

```bash
# Scan configs and migrate plaintext secrets to keychain
passkey init                    # Auto-detect all tools
passkey init --tool claude      # Specific tool
passkey init --tool vscode

# Show security status across all tools
passkey status

# Run diagnostics
passkey doctor

# List MCP servers across tools
passkey servers
```

Supported tools: `claude`, `claude_desktop`, `gemini`, `vscode`, `cursor`, `opencode`, `windsurf`, `cline`, `zed`

### Export and Backup

```bash
# Export all entries to file (owner-only permissions set automatically)
passkey export backup.json

# Export specific entries
passkey export backup.json --entries github openai

# Export metadata only (no secret values)
passkey export backup.json --no-secrets

# Encrypted export (AES-256-GCM + scrypt)
passkey export backup.passkey.enc --encrypt
```

### Import

```bash
# Import from passkey backup
passkey import backup.json

# Preview without importing
passkey import backup.json --dry-run

# Handle duplicates: skip (default), overwrite, merge
passkey import backup.json --mode merge

# Import from encrypted bundle
passkey import backup.passkey.enc --decrypt

# Import from Chrome password export (CSV)
passkey import passwords.csv --filter github.com

# Import from an existing MCP config file
passkey import claude_desktop_config.json
```

### Audit Log

```bash
passkey audit              # View recent operations
passkey audit --limit 50   # Show more entries
passkey audit --clear      # Clear the log
```

### Verify Entry Health

```bash
# Exit non-zero if any required fields are missing
passkey check github GITHUB_TOKEN GITHUB_USERNAME
```

## Authentication

Passkey requires OS-level authentication before any secret access. This uses your system's PAM configuration:

- **macOS with Touch ID**: Touch ID prompt (if configured in `/etc/pam.d/sudo`)
- **macOS without Touch ID**: Admin password dialog
- **Linux**: PolicyKit dialog (GNOME/KDE) or password prompt
- **Windows**: UAC elevation dialog

Credentials are cached for 5 minutes (same as `sudo`).

## MCP Config Example

**Before (insecure — secret in plaintext):**
```json
{
  "mcpServers": {
    "github": {
      "command": "python",
      "args": ["-m", "github.server"],
      "env": {
        "GITHUB_TOKEN": "ghp_PLAINTEXT_SECRET_HERE"
      }
    }
  }
}
```

**After (secure — secret loaded from keychain at runtime):**
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

## MCP Server Mode

Passkey can run as an MCP server itself, letting AI assistants invoke passkey tools via natural language:

```json
{
  "mcpServers": {
    "passkey": {
      "command": "passkey-mcp-server"
    }
  }
}
```

Available tools: `passkey_list`, `passkey_fields`, `passkey_status`, `passkey_doctor`, `passkey_wrap_server`.

AI assistants can **discover** entry names but never see secret values — secrets only flow out via `passkey run`.

## Data Storage

| Platform | Data directory |
|----------|---------------|
| macOS    | `~/Library/Application Support/passkey/` |
| Linux    | `~/.config/passkey/` (respects `$XDG_CONFIG_HOME`) |
| Windows  | `%APPDATA%\passkey\` |

Secrets themselves are stored in the **system keychain**, not on disk. The data directory holds metadata (lock file, audit log).

## Security

- **Encrypted at rest**: System keychain handles encryption (AES-256-GCM on macOS, DPAPI on Windows)
- **No secrets logged**: Only entry names and operation types appear in the audit log
- **Hidden input**: `getpass` used for all secret entry
- **Clipboard auto-clear**: Copied secrets cleared after 30 seconds
- **Secure export**: Files created with `chmod 600` (owner-only)
- **Encrypted bundles**: AES-256-GCM + scrypt (N=2^20) for portable transfer
- **LLM-safe**: AI assistants can list entries but never read values

See [docs/SECURITY.md](docs/SECURITY.md) for full details.

## Troubleshooting

### "Failed to access Keychain" (macOS)
Grant Terminal / Python keychain access in **System Settings → Privacy & Security**.

### Touch ID not working
Ensure `pam_tid.so` is configured in `/etc/pam.d/sudo`:
```bash
sudo sed -i '' '2i\
auth       sufficient     pam_tid.so
' /etc/pam.d/sudo
```

### Linux headless / no keyring daemon
Set a backend explicitly:
```bash
export PYTHON_KEYRING_BACKEND=keyring.backends.SecretService.Keyring
# or for headless environments:
export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring
```

### Entry not found
```bash
passkey list   # check exact names (case-sensitive)
```

### Import shows "skipped (exists)"
```bash
passkey import backup.json --mode merge
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
ruff check passkey/
```

## License

MIT — see [LICENSE](LICENSE)
