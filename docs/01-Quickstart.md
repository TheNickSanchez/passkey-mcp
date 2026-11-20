[Home](Home.md) › Getting Started › **Quickstart**

---

# Quickstart

Install `passkey-mcp`, migrate plaintext secrets out of your AI tool configs, and inject your first secret from the OS keychain in under two minutes.

---

## 1. Install `passkey-mcp`

Install into an isolated tool environment using `uv` or `pipx` (Python 3.10+ required):

```bash
uv tool install passkey-mcp
```

Or with `pipx`:

```bash
pipx install passkey-mcp
```

Verify the CLI and MCP server binaries are on your `PATH`:

```bash
passkey --version
# passkey 0.9.x

passkey doctor
```

> **Tip:** Installing `passkey-mcp` never modifies your editor configs automatically. Config wrapping only happens when you explicitly run `passkey init`.

### Enable Tab Completion (Optional)

```bash
# Zsh (macOS default — add to ~/.zshrc)
eval "$(passkey completion --zsh)"

# Bash (add to ~/.bashrc)
eval "$(passkey completion --bash)"

# Fish
passkey completion --fish > ~/.config/fish/completions/passkey.fish
```

---

## 2. First Run: Context-Aware `passkey`

Running bare `passkey` in an interactive terminal adapts automatically to your machine's state:

```bash
passkey
```

On your very first run (before `<data_dir>/settings.json` records a `default-policy` choice), `passkey` asks once how you want AI agents authorized to use your credentials:

1. **`Touch ID once per 10m agent session (Recommended — like 1Password)`** → `default-policy = session` *(macOS Touch ID default)*
2. **`Auto-approve / YOLO (zero prompts — fastest for local dev & background MCP)`** → `default-policy = allow` *(Windows / headless Linux default)*
3. **`Strict Touch ID on every single command (maximum lock-down)`** → `default-policy = prompt`

Your choice is saved atomically to `settings.json` so onboarding never asks twice (change anytime via `passkey config default-policy <session|allow|prompt>`).

| Machine State | What Bare `passkey` Does |
| :--- | :--- |
| **0 entries + plaintext MCP secrets detected** | Lists every exposed server (`Claude`, `Cursor`, `VS Code`, `Gemini`, etc.) and offers 1-step migration (`passkey init`). |
| **0 entries + clean machine** | Launches quickstart menu to create your first secret (`passkey new`) or view examples. |
| **Entries already exist** | Opens the interactive fuzzy entry browser (`passkey get`). |

---

## 3. Migrate Existing MCP Configs (`passkey init`)

If your MCP client configs (`~/.cursor/mcp.json`, `~/.claude.json`, `claude_desktop_config.json`, `~/.gemini/settings.json`, `.vscode/mcp.json`, etc.) currently hold API keys in `env`, preview and migrate them:

```bash
# 1. Preview detected secrets without modifying any files
passkey init --dry-run

# 2. Migrate secrets to OS keychain and wrap MCP server commands
passkey init

# Or migrate a single tool non-interactively
passkey init --tool cursor --yes
```

### What `passkey init` Changes

1. **Extracts secrets** (keys matching `TOKEN`, `SECRET`, `API_KEY`, `PASSWORD`, `AUTH`, embedded `://user:pass@` URIs, or known token prefixes like `sk-`, `ghp_`, `xoxb-`, `AKIA`) into your OS keychain, while leaving non-secret variables (`NODE_ENV`, `PYTHONPATH`, `PROJECT_ID`) inline.
2. **Saves a `0o600` timestamped backup** of the original config in `<data_dir>/backups/`—never cluttering your git workspace with `.backup` files.
3. **Keeps background stdio MCP servers boot-safe (`policy = allow`)** by default so launching Cursor, Claude Desktop, or VS Code never triggers concurrent Touch ID prompts across 6 servers at once—while printing a one-line tip showing how to gate high-privilege MCP servers (e.g., `passkey policy jamf session`) or pass `--policy session` explicitly.
4. **Rewrites the server launch command** to inject credentials at runtime:

```json
{
  "mcpServers": {
    "github": {
      "command": "passkey",
      "args": ["run", "--quiet", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

### Audit Status & Diagnostics

```bash
# Check which MCP servers are secured, exposed, or partial across all tools
passkey status
passkey status --json

# Run full keychain, PATH, config, and backup diagnostics
passkey doctor
passkey doctor --deep --json
```

### Clean Rollback (`passkey unwrap`)

`passkey init` is never a one-way door. Restore inline MCP server commands at any time:

```bash
# Preview changes first
passkey unwrap --dry-run

# Restore original command structure (secrets stay safely in keychain)
passkey unwrap --tool cursor

# Or write secret values back into the config file if uninstalling passkey
passkey unwrap --tool cursor --restore-secrets
```

---

## 4. Create & Run Your First Secret Manually

```bash
# 1. Create an entry named 'stripe' (opens masked prompt — never put secrets in argv)
passkey new stripe

# 2. Inspect entry metadata (field names, policy, timestamps — never values)
passkey info stripe

# 3. Run any command with 'stripe' injected into its environment
passkey run stripe -- python app.py
```

> **Security Note:** Any secret value (`len >= 4`) printed by `python app.py` to `stdout` or `stderr` is automatically scrubbed to `<concealed by passkey>` before reaching your terminal scrollback or an AI agent's context window.

---

[← Home](Home.md) · [Next: Managing Secrets →](02-Managing-Secrets.md)
