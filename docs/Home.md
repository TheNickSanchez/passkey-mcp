**Home**

---

# Passkey (`passkey-mcp`) Wiki

**`passkey-mcp` is a local OS-keychain secret injector for AI coding agents, MCP servers, and developer CLIs.**

Instead of scattering API tokens across `.env` files, `mcp.json` configs, `~/.zshrc` exports, and AI chat transcripts, `passkey` stores named credential sets inside your operating system's native keychain (`macOS Keychain`, `Windows Credential Manager`, or `Linux Secret Service`) and injects them into child processes at runtime—while scrubbing secret values from `stdout` and `stderr` automatically.

> **Security Note:** `passkey-mcp` is a **local keychain injector**, not a cloud password manager, shared SaaS vault, or 1Password replacement. There is no server, no telemetry, and no network sync. Secret values never leave your machine and never enter AI model context.

---

## Architecture in 30 Seconds

```text
┌───────────────────────────────────────────────────────────────────────────┐
│ AI Agent / Developer Terminal (Claude Code, Cursor, Gemini CLI, Codex)    │
│                                                                           │
│  1. Inspects metadata ONLY (entry names, field keys, policy, leases)      │
│     via `--json` or `passkey-mcp-server` — NEVER sees secret values.      │
│  2. Captures missing/expired keys via native OS hidden dialog             │
│     (`passkey request` / `passkey_request_secret`) -> straight to OS ACL. │
│  3. Runs commands via `passkey exec -- pytest` or `passkey run ...`       │
└───────────────────────────────┬───────────────────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ passkey Runtime Broker                                                    │
│  • Verifies HMAC-signed repo manifest (`trusted_projects.json`)           │
│  • Enforces `allow` | `session` (1 Touch ID / session) | `prompt` policy  │
│  • Loads secrets from OS Keychain (`keyring` service = "passkey")         │
│  • Injects env vars into child process ONLY                               │
│  • Scrubs raw + JSON-escaped secrets -> `<concealed by passkey>`          │
└──────────────┬────────────────────────────────────────┬───────────────────┘
               │                                        │
               ▼                                        ▼
┌──────────────────────────────┐        ┌───────────────────────────────────┐
│ OS Native Keychain           │        │ Child Process (`pytest`, MCP srv) │
│  • macOS Keychain + Touch ID │        │  • Receives `STRIPE_SECRET_KEY`   │
│  • Windows Credential Mgr    │        │  • Output scrubbed before agent   │
│  • Linux Secret Service      │        │    or terminal scrollback sees it │
└──────────────────────────────┘        └───────────────────────────────────┘
```

---

## Choose Your Path

| Goal | Start Here | Time |
| :--- | :--- | :--- |
| **I want to secure my existing AI IDE/CLI MCP configs in 10 seconds** | [01 — Quickstart](01-Quickstart.md) | 2 min |
| **I want to store, browse, rotate, and back up my own API keys** | [02 — Managing Secrets](02-Managing-Secrets.md) | 5 min |
| **I want to run scripts, `.env` templates, or `gh`/`aws` CLIs without `.env` files** | [03 — Running & Injecting](03-Running-and-Injecting.md) | 5 min |
| **I want to onboard Claude Code, Cursor, Gemini CLI, or Codex** | [04 — Onboarding AI Agents](04-AI-Agent-Onboarding.md) | 3 min |
| **I want to share a zero-secret repo setup with my team** | [05 — Team Workflows](05-Team-Workflows.md) | 4 min |

---

## Complete Wiki Index

### Getting Started
* **[01 — Quickstart](01-Quickstart.md):** Install with `pipx` or `uv`, migrate exposed MCP configs via `passkey init`, verify with `passkey doctor`, and create your first entry.

### Core Guides
* **[02 — Managing Secrets](02-Managing-Secrets.md):** Interactive masked input (`•` bullets + counter), `fields` vs. non-secret `config`, fuzzy lookup, rotation, templates, and `AES-256-GCM` + `Scrypt` bundles.
* **[03 — Running & Injecting](03-Running-and-Injecting.md):** `passkey run`, zero-config `passkey exec`, `passkey://` URIs, `passkey inject`, ephemeral FIFO `.env` mounts, and `passkey plugin` wrappers.
* **[04 — Onboarding AI Agents](04-AI-Agent-Onboarding.md):** Connect `passkey-mcp-server`, install guard hooks + `SKILL.md` rules, and test the 3-turn autonomous workflow (`find` → `request` → `exec`).
* **[05 — Team Workflows](05-Team-Workflows.md):** Committable `.env.passkey` / `.passkey.toml` manifests, HMAC repo trust (`passkey project`), and inline `pk1:` encrypted peer sharing (`passkey share` / `upload` / `receive`).

### Security & Advanced
* **[06 — Security & Biometrics](06-Security-and-Biometrics.md):** Threat model, OS keychain boundaries, `allow` / `session` / `prompt` Touch ID policies, scoped leases, and HMAC hash-chained `audit.log`.
* **[07 — Browser Agent Autofill](07-Browser-Agent-Autofill.md):** Deterministic Chrome DevTools Protocol (`CDP`) credential & cookie injection (`passkey browser-fill`) outside the LLM context window.

### Reference
* **[08 — CLI Command Reference](08-CLI-Command-Reference.md):** Every command, subcommand group, flag, environment variable, and exit code (`0`, `1`, `2`).
* **[09 — MCP Tools & Prompts Reference](09-MCP-Tools-and-Prompts-Reference.md):** All 13 FastMCP tools, input/output schemas, `ToolAnnotations`, policy gates, and 3 `@mcp.prompt()` playbooks.
* **[10 — Troubleshooting & FAQ](10-Troubleshooting-and-FAQ.md):** Fixes for macOS Seatbelt sandboxes, Linux headless keyrings, stale `.env` FIFOs, `passkey unwrap` recovery, and audit verification.

---

**Next:** [Quickstart →](01-Quickstart.md)
