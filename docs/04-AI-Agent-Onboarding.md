[Home](Home.md) › Core Guides › **Onboarding AI Agents**

---

# Onboarding AI Agents

Set up Claude Code, Cursor, Gemini CLI, Codex, VS Code, Windsurf, Cline, OpenCode, or Zed so your coding agents can discover, request, rotate, and inject secrets autonomously—**without ever seeing a single secret value**.

---

## Step 1: Connect `passkey-mcp-server` (and Migrate Existing MCP Secrets)

First, migrate any plaintext tokens already sitting in your AI tool configs into your OS keychain:

```bash
passkey init
```

Next, register `passkey-mcp-server` in your AI coding tool so the agent gains structured discovery, preflight, and out-of-band secret-request tools:

### Quick CLI Setup (Claude Code)

```bash
claude mcp add passkey -- passkey-mcp-server
```

### Config File Setup Across All Supported Tools

Add `"passkey": { "command": "passkey-mcp-server" }` to your tool's MCP config file:

| AI Tool | `--tool` Adapter Name | Global Config Path (macOS / Linux) | Project Config Path |
| :--- | :--- | :--- | :--- |
| **Claude Code** | `claude` | `~/.claude.json` *(Linux: `~/.config/claude/claude.json`)* | — |
| **Claude Desktop** | `claude_desktop` | `~/Library/Application Support/Claude/claude_desktop_config.json` *(Linux: `~/.config/Claude/claude_desktop_config.json`)* | — |
| **Cursor** | `cursor` | `~/.cursor/mcp.json` | `.cursor/mcp.json` |
| **Gemini CLI** | `gemini` | `~/.gemini/settings.json` | `.gemini/settings.json` |
| **VS Code (Copilot)** | `vscode` | `~/Library/Application Support/Code/User/mcp.json` *(Linux: `~/.config/Code/User/mcp.json`)* | `.vscode/mcp.json` |
| **Windsurf** | `windsurf` | `~/.codeium/windsurf/mcp_config.json` | — |
| **Cline** | `cline` | `.../Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` | — |
| **OpenCode** | `opencode` | `~/.config/opencode/opencode.json` | `opencode.json` |
| **Zed** | `zed` | `~/.config/zed/settings.json` | `.zed/settings.json` |

Standard JSON snippet (`mcpServers`):

```json
{
  "mcpServers": {
    "passkey": {
      "command": "passkey-mcp-server"
    }
  }
}
```

> **Tip:** For CLI-only agents without MCP configured (such as standalone shell harnesses), set `export PASSKEY_OUTPUT=json` in the agent's environment so every `passkey` CLI call emits deterministic JSON—including structured `error_code` and `remediation_command` envelopes on errors.

---

## Step 2: Install Guard Hooks & Agent Skills in One Command

Inside your project repository, install pre-execution secret-guard hooks **and** agent skill files in a single command:

```bash
passkey hook install --tool all --with-skill
```

This non-destructively writes:
* **Pre-tool guard hooks:** `.claude/settings.json` (`PreToolUse`), `.cursor/hooks.json` (`beforeShellExecution`, `beforeReadFile`), and `.gemini/settings.json` (`BeforeTool`)
* **Agent golden-rule instructions:** `.claude/skills/passkey/SKILL.md`, `.cursor/rules/passkey.mdc`, `.gemini/skills/passkey/SKILL.md`, and a bounded marker block inside `AGENTS.md`

*(To install only the Markdown skill/rules files without hooks, run `passkey skill install --tool all`.)*

### What `passkey hook check` Blocks Automatically

| Blocked Agent Action | Allowed Safe Alternative Suggested to Agent |
| :--- | :--- |
| Reading `.env`, `.env.local`, `.env.production`, `*.backup`, `*.enc`, `*.passkey` (via File Read tools or `cat`/`grep`/`rg`/`sed`/`awk`/`head`/`tail`/`base64`/`curl`) | Read `.env.example`, `.env.template`, or `.env.passkey`, and run `passkey find` / `passkey exec` |
| `passkey get` / `passkey entry get` (overwrites user clipboard) | `passkey info <entry> --json` + `passkey run -q <entry> -- <cmd>` |
| Plaintext `passkey export <file>` or `passkey export -` | `passkey list --json` or `passkey export <file> --no-secrets` |
| `passkey generate --no-copy` (prints raw secret to agent `stdout`) | `passkey request <entry> --fields <VAR>` |
| `passkey inject --stdout` or `passkey inject -o -` | `passkey inject -i <tpl> -o <gitignored-file>` |

---

## Step 3: How the 3-Turn Autonomous Agent Loop Works

Once onboarded, your agent never stalls on interactive prompts and never asks you to paste API keys into chat:

1. **Turn 1 — Reverse Lookup (`passkey_find` / `passkey find`):**
   Code fails with `KeyError: 'RESEND_API_KEY'`, or the repo has a `.env.example`. The agent runs:
   ```bash
   passkey find --from-file .env.example --json
   ```
   `passkey` checks exact keys, service aliases (`GH_TOKEN` ↔ `GITHUB_TOKEN`), and entry-scoped generic names (`RESEND_API_KEY` → `resend/API_KEY`) without reading secret values.

2. **Turn 2 — Out-of-Band Native OS Popup (`passkey_request_secret` / `passkey request`):**
   If a key is missing—or an API returns `401 Unauthorized` on an expired token—the agent triggers a native hidden OS dialog directly on your desktop:
   ```bash
   # Capture a missing secret (opens macOS hidden dialog / Linux zenity --password)
   passkey request resend --fields RESEND_API_KEY --policy session \
     --hint "Resend Dashboard -> API Keys" --json

   # Or rotate an expired token (fires macOS Notification Center alert + Rotate modal)
   passkey request resend --fields RESEND_API_KEY \
     --reason "HTTP 401 Unauthorized: token expired" \
     --hint "Create a fresh key in Resend Dashboard" --json
   ```
   You paste the key into the OS dialog; it saves straight into your OS Keychain (`status: "created"` / `"rotated": true`), and the agent only receives field metadata.

3. **Turn 3 — Zero-Config Execution (`passkey exec`):**
   The agent bootstraps `.env.passkey` (`passkey project init`) and runs tests via:
   ```bash
   passkey exec -q -- pytest
   ```
   With `policy = session`, you approve **one** Touch ID prompt (`Passkey: unlock 'resend' for claude-code (10m session)`), and every test run for the rest of that agent session runs uninterrupted with `<concealed by passkey>` stream masking active.

---

## Step 4: Copy-Paste Verification Prompt

Paste this prompt into your AI coding agent right after onboarding to verify your setup end-to-end:

```text
Verify your passkey integration in 3 steps without exposing any secret values:
1. Call `passkey_doctor` (or `passkey doctor --json`) and `passkey_status` to confirm keychain health and MCP config status.
2. Call `passkey_list` and `passkey_project_status` for the current workspace and summarize whether a `.env.passkey` or `.passkey.toml` manifest is present.
3. Confirm that interactive commands fail fast safely by running `passkey --no-input get --json` and reporting the returned `error_code`.
```

---

[← Running & Injecting](03-Running-and-Injecting.md) · [Next: Team Workflows →](05-Team-Workflows.md)
