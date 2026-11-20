<div align="center">

# passkey-mcp

**Zero-plaintext secrets for AI coding agents and the terminal.**

Store API keys and credentials in your native OS Keychain (`macOS Keychain`, `Windows Credential Manager`, `Linux Secret Service`) and inject them into MCP servers and CLI processes at runtime—with real-time output masking and zero secrets in config files, shell history, or LLM context.

[![PyPI](https://img.shields.io/pypi/v/passkey-mcp?color=0A7EA4&label=PyPI)](https://pypi.org/project/passkey-mcp/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![MCP Compatible](https://img.shields.io/badge/MCP-FastMCP%201.x-111827)](docs/09-MCP-Tools-and-Prompts-Reference.md)
[![OS Keychain Native](https://img.shields.io/badge/Keychain-macOS%20%7C%20Linux%20%7C%20Windows-0F766E)](docs/06-Security-and-Biometrics.md)
[![Zero Daemons](https://img.shields.io/badge/Architecture-Zero%20Daemons%20%7C%20Local%20Only-334155)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-22C55E)](LICENSE)

[**Quickstart**](#60-second-quickstart) · [**How It Works**](#how-it-works) · [**AI Agent Workflows**](#ai-agent-workflows) · [**Security Model**](#security-model) · [**Documentation Wiki**](#documentation-wiki)

</div>

---

> **Positioning:** `passkey-mcp` is a local OS-keychain secret injector—**not** a team password manager, shared cloud vault, or 1Password replacement. No cloud sync, no background daemon, no telemetry. Alpha (`0.9.x`).

## How It Works

AI coding tools normally store MCP server tokens in plaintext JSON on disk (`~/.cursor/mcp.json`, `~/.claude.json`, `claude_desktop_config.json`). One command (`passkey init`) moves those tokens into your OS Keychain, saves a `0o600` backup in `<data_dir>/backups/`, and rewrites the launch command to inject secrets in memory at startup:

```diff
 {
   "mcpServers": {
     "stripe": {
-      "command": "npx",
-      "args": ["-y", "@stripe/mcp"],
-      "env": {
-        "STRIPE_SECRET_KEY": "sk_live_51N..."
-      }
+      "command": "passkey",
+      "args": ["run", "--quiet", "stripe", "--", "npx", "-y", "@stripe/mcp"]
     }
   }
 }
```

Need to leave `passkey`? Run `passkey unwrap` at any time to restore inline commands cleanly.

---

## 60-Second Quickstart

### Install

```bash
uv tool install passkey-mcp
# or: pipx install passkey-mcp
```

*(Working from a local git clone? Run `uv sync && uv run passkey --help`.)*

### Step 1 — Secure Existing MCP Configs in One Command

```bash
passkey init --dry-run   # Preview detected plaintext MCP secrets across installed tools
passkey init             # Migrate tokens to OS Keychain and wrap server configs
passkey status           # Verify all servers report 'secured'
```

### Step 2 — Store & Run Your Own Secrets

```bash
passkey new stripe                       # Masked input ('•' bullets + live char counter)
passkey run stripe -- pytest             # Inject into child env with stdout/stderr masking
```

### Step 3 — Onboard Your AI Coding Agents

```bash
# Install PreToolUse secret-guard hooks + SKILL.md / .mdc / AGENTS.md rules in one shot
passkey hook install --tool all --with-skill
```

Add `passkey-mcp-server` to your MCP client (`claude mcp add passkey -- passkey-mcp-server`) or drop this into your client's `mcp.json`:

```json
{
  "mcpServers": {
    "passkey": {
      "command": "passkey-mcp-server"
    }
  }
}
```

Once connected, agents gain **13 secret-free MCP tools** (`passkey_find`, `passkey_project_status`, `passkey_request_secret`, `passkey_entry_info`, `passkey_preflight_run`, `passkey_doctor`, ...) and **3 guided `@mcp.prompt()` playbooks** (`setup-project-secrets`, `debug-missing-credential`, `migrate-exposed-mcp-configs`).

---

## AI Agent Workflows

### 1. Real-Time Stream Scrubbing (`SecretMasker`)

Even if a test crash, traceback, or rogue `print(os.environ)` dumps an injected token, `passkey` scrubs raw UTF-8 and JSON-escaped secret values (`len >= 4`, across pipe chunk boundaries) before they reach terminal scrollback or LLM context:

```bash
$ passkey run -q stripe -- python3 -c 'import os; print("Token:", os.environ["STRIPE_SECRET_KEY"])'
Token: <concealed by passkey>
```

### 2. Out-of-Band Native OS Secret Popups (`passkey_request_secret`)

When an entry is missing—or an API returns `401 Unauthorized` on an expired key—your agent doesn't stall or ask you to paste secrets into chat. It triggers a native macOS/Linux hidden-input dialog directly on your desktop that saves straight into your OS Keychain:

```bash
# Missing credential -> pops native hidden dialog ("Passkey - Secret Request")
passkey request stripe_dev --fields STRIPE_SECRET_KEY,WEBHOOK_SECRET --policy session \
  --hint "Stripe Dashboard -> Developers -> API keys" --json

# Expired credential -> fires macOS Notification banner + "Passkey - Rotate Secret" modal
passkey request resend --fields RESEND_API_KEY \
  --reason "HTTP 401 Unauthorized: API token expired" \
  --hint "Resend Dashboard -> API Keys -> Create API Key" --json
```

The agent receives only `{"ok": true, "status": "updated", "fields_saved": ["RESEND_API_KEY"], "rotated": true}`—never the secret.

### 3. Biometric Touch ID Session Leases (`policy = session`)

Balance hardware biometric security with uninterrupted multi-turn agent loops using three per-entry policies (`passkey policy <entry> <mode>`):

| Policy | Biometric Behavior | Ideal Use Case |
| :--- | :--- | :--- |
| **`allow`** *(default)* | Headless OS Keychain access (no extra prompt) | Background MCP servers & everyday dev keys |
| **`session`** | **1 Touch ID tap** unlocks the calling agent session (`10m` default TTL, bound to `(ancestor_pid, start_time)`) | Staging/cloud APIs used across 20-turn coding loops |
| **`prompt`** | **Touch ID on every single invocation** unless an explicit `passkey lease grant` is active | Production databases, billing, & root credentials |

### 4. Zero-Config Repo Execution (`passkey project init` + `passkey exec`)

Commit a secret-free `.env.passkey` pointer manifest to git so humans and agents never have to stitch entry names together:

```bash
# Scan .env.example (refuses live .env!), map matching keychain entries, and write .env.passkey
passkey project init

# Run from anywhere inside the repo — HMAC-verified against trusted_projects.json
passkey exec -q -- pytest
```

### 5. Peer-to-Peer Encrypted Token Sharing (`passkey share` + `passkey upload`)

Hand a credential set to a teammate over Slack/Teams without writing files to disk or pasting plaintext keys:

```bash
# Sender: fuzzy-match entry, copy compact AAD-authenticated pk1:... token to clipboard (120s auto-clear),
# and print a random 8-word Scrypt passphrase for a separate channel
passkey share stripe_dev

# Recipient: paste the pk1:... token & passphrase at masked prompts, preview fields, and save to keychain
passkey upload
```

---

## Security Model

```text
┌───────────────────────────────────────────────────────────────────────────┐
│ AI Agent / LLM Context (Claude Code, Cursor, Gemini CLI, Codex, VS Code)  │
│  • Sees ONLY: entry names, field keys, policy, lease status (`--json`)    │
│  • Blocked from `.env`, `*.backup`, `*.enc`, `passkey get` via PreToolUse │
│  • Receives child stdout/stderr with secrets -> `<concealed by passkey>`  │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │  MCP stdio / CLI subprocess
                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ passkey Broker (In-Memory, Zero Background Daemons)                       │
│  1. Verifies repo manifest SHA-256 against HMAC `trusted_projects.json`   │
│  2. Enforces `allow` | `session` (`proc_pidinfo` lineage) | `prompt` ACL  │
│  3. Reads secret payload from OS Keychain (`service="passkey"`)           │
│  4. Injects env vars into child process ONLY & scrubs output streams      │
│  5. Appends caller-attributed record to HMAC hash-chained `audit.log`     │
└───────────────────────────────────────────────────────────────────────────┘
```

* **OS Keychain at Rest:** Credentials, config values, authoritative per-entry policies, and all three internal 256-bit HMAC keys (`__audit_hmac_key__`, `__lease_hmac_key__`, `__trust_hmac_key__`) live in your OS Keychain—`<data_dir>` (`0o700`) stores `0o600` secret-free metadata (`entries.json` v2) so discovery, `<TAB>` completion, and `--dry-run` preflight trigger zero Keychain prompts.
* **Authenticated Portability (`pk1:` & `PK01`):** `passkey share` / `passkey upload` exchange compact URL-safe `pk1:...` tokens authenticated with `AES-256-GCM` (`"pk1:" + header` AAD) + `Scrypt` (`N=2^20, r=8, p=1`), while `passkey export --encrypt` and `passkey share -o` write `O_EXCL`, `0o600` `PK01` bundles.
* **Tamper-Evident Audit Chain:** Every operation records `actor` attribution (`human` vs. `agent` client) in an HMAC-SHA256 hash chain (`passkey audit --verify`).
* **Pre-Execution Agent Guardrails:** `passkey hook check` blocks agent file/shell reads of `.env`, `*.backup`, `*.enc`, `passkey get`, `passkey share`/`upload`/`receive`, and plaintext `passkey export` (exit code `2`).
* **Loopback-Only Browser Broker:** `passkey browser-fill` verifies exact `(scheme, host, port)` `ORIGIN` match over direct loopback CDP WebSockets (`127.0.0.1`) before injecting login fields outside LLM context.
* **Honest Boundaries:** Same-UID processes on an unlocked machine share user-level OS privileges (and on macOS `pipx`/venv installs, Keychain ACLs bind to the underlying `python3` binary). See [SECURITY.md](SECURITY.md) for the full threat model and vulnerability reporting policy.

---

## Supported MCP Clients & CLI Wrappers

| Category | Supported Integrations |
| :--- | :--- |
| **MCP Clients (`passkey init` / `status`)** | **Claude Code** (`claude`) · **Claude Desktop** (`claude_desktop`) · **Cursor** (`cursor`) · **VS Code** (`vscode`) · **Gemini CLI** (`gemini`) · **Windsurf** (`windsurf`) · **Cline** (`cline`) · **OpenCode** (`opencode`) · **Zed** (`zed`) |
| **Agent Hooks & Skills (`hook` / `skill`)** | **Claude Code** (`.claude/settings.json`, `SKILL.md`) · **Cursor** (`.cursor/hooks.json`, `passkey.mdc`) · **Gemini CLI** (`.gemini/settings.json`, `SKILL.md`) · **Universal** (`AGENTS.md`) |
| **CLI Plugins (`passkey plugin init`)** | `claude` · `codex` · `openai` · `gemini` · `cursor-agent` · `gh` · `aws` · `wrangler` · `vercel` · `stripe` |

Keep `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `ANTHROPIC_API_KEY`, and `OPENAI_API_KEY` out of `~/.zshrc` permanently with scoped CLI wrappers (`session > .passkey.toml > global > auto`):

```bash
passkey plugin init gh                      # Bind 'gh' CLI to your 'github' keychain entry
passkey plugin init aws --scope dir         # Bind 'aws' per-repo inside committable .passkey.toml
passkey plugin run gh -- pr status          # Injects GH_TOKEN & scrubs output streams
```

### Data Storage Locations

| Platform | Metadata Directory (`0o700` dir, `0o600` files — zero secret values on disk) |
| :--- | :--- |
| **macOS** | `~/Library/Application Support/passkey/` |
| **Linux** | `$XDG_CONFIG_HOME/passkey/` or `~/.config/passkey/` |
| **Windows** | `%APPDATA%\passkey\` |

*(Override anytime with `PASSKEY_DATA_DIR`. Upgrading `passkey-mcp` via `pipx` or `uv tool` preserves every stored keychain entry, policy, lease, and audit record.)*

---

## Documentation Wiki

Explore the complete documentation in [`docs/Home.md`](docs/Home.md):

| Guide | Topics Covered |
| :--- | :--- |
| [**Wiki Home**](docs/Home.md) | 30-second architecture overview & "Choose Your Path" router |
| [**01 — Quickstart**](docs/01-Quickstart.md) | `pipx` / `uv` setup, first-run onboarding, `passkey init`, `doctor`, and `unwrap` |
| [**02 — Managing Secrets**](docs/02-Managing-Secrets.md) | Masked input shortcuts (`Ctrl+R`/`Tab`, `Ctrl+U`), `fields` vs. `config`, rotation, templates, and bundles |
| [**03 — Running & Injecting**](docs/03-Running-and-Injecting.md) | `passkey run`, `passkey exec`, `passkey://` `$VAR` URIs, `inject`, ephemeral `.env` FIFOs, and CLI `plugin` wrappers |
| [**04 — Onboarding AI Agents**](docs/04-AI-Agent-Onboarding.md) | Connecting `passkey-mcp-server`, guard hooks, 3-turn autonomous workflow, and verification prompt |
| [**05 — Team Workflows**](docs/05-Team-Workflows.md) | Committable `.env.passkey` & `.passkey.toml` manifests, HMAC repo trust, and inline `pk1:` `share` / `upload` |
| [**06 — Security & Biometrics**](docs/06-Security-and-Biometrics.md) | Threat model, OS boundaries, `allow` / `session` / `prompt` Touch ID policies, leases, and `audit.log` |
| [**07 — Browser Agent Autofill**](docs/07-Browser-Agent-Autofill.md) | Loopback Chrome DevTools (`CDP`) login & cookie autofill (`passkey browser-fill`) |
| [**08 — CLI Command Reference**](docs/08-CLI-Command-Reference.md) | All commands, subcommands, global flags, `PASSKEY_OUTPUT=json`, settings, and exit codes |
| [**09 — MCP Tools & Prompts**](docs/09-MCP-Tools-and-Prompts-Reference.md) | All 13 FastMCP tools, schemas, `ToolAnnotations`, config gates, and 3 `@mcp.prompt()` playbooks |
| [**10 — Troubleshooting & FAQ**](docs/10-Troubleshooting-and-FAQ.md) | Fixes for macOS Keychain ACL prompts, Seatbelt sandboxes, Linux keyrings, stale FIFOs, and `unwrap` recovery |

### Essential Commands Cheat Sheet

```bash
passkey new <entry>                        # Create an entry via masked interactive prompt
passkey find <ENV_VAR> --json              # Reverse-lookup which entry stores an env var
passkey request <entry> -f <VAR> --json    # Capture/rotate a secret via native OS popup
passkey project init                       # Generate committable .env.passkey from .env.example
passkey exec -q -- <command>               # Auto-inject repo manifest secrets with output masking
passkey run -q <entry> -- <command>        # Inject explicit entry secrets into any command
passkey policy <entry> session             # Require 1 Touch ID tap per 10m agent session
passkey share <entry>                      # Copy encrypted pk1: share token + 8-word passphrase
passkey upload                             # Decrypt a pasted pk1: token into OS Keychain
passkey init                               # Migrate plaintext MCP server tokens to OS Keychain
passkey doctor --deep                      # Verify Keychain, PATH, configs, and HMAC audit chain
passkey audit --verify                     # Cryptographically verify tamper-evident audit.log
```

---

## Development & License

Requires Python 3.10+ and [`uv`](https://docs.astral.sh/uv/) (see [CONTRIBUTING.md](CONTRIBUTING.md) and [`docs/architecture.mmd`](docs/architecture.mmd)):

```bash
uv sync
uv run pytest -q
uv run ruff check passkey/ tests/
```

MIT License — see [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
