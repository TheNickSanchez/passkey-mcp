[Home](Home.md) › Reference › **CLI Command Reference**

---

# CLI Command Reference

Complete reference for every `passkey` command, subcommand group, flag, setting, environment variable, and exit code in `v0.8.x`.

---

## Global Flags, Environment Variables & Exit Codes

### Global Flags

| Flag | Description |
| :--- | :--- |
| `-h`, `--help` | Show categorized help output and exit (`0`). |
| `-V`, `--version` | Print installed `passkey <version>` and exit (`0`). |
| `--no-input` | Never prompt on `stdin` or launch TUI pickers; fail fast with exit code `2` (`INTERACTIVE_REQUIRED`). Accepted before or after subcommand names. |

### Environment Variables

| Variable | Effect |
| :--- | :--- |
| `PASSKEY_OUTPUT=json` | Automatically enables deterministic `--json` output across read/diagnostic commands and emits structured JSON error envelopes (`{"ok": false, "error_code": ..., ...}`). On child-wrapping commands (`run`, `exec`, `plugin run`), JSON error envelopes are written to `stderr` so child `stdout` pipelines stay untouched. |
| `PASSKEY_NO_INPUT=1` | Equivalent to passing `--no-input` globally. |
| `PASSKEY_ALLOW_INTERACTIVE=1` | Overrides automatic headless fail-fast inside detected AI agent PTY environments (`CLAUDECODE`, `CURSOR_AGENT`, `GEMINI_CLI`, `ANTIGRAVITY_AGENT`, `CODEX_ENV`, `OPENAI_CODEX`). |
| `PASSKEY_DATA_DIR=<path>` | Overrides platform data directory (`~/Library/Application Support/passkey` on macOS, `~/.local/share/passkey` on Linux, `%LOCALAPPDATA%\passkey` on Windows). |
| `PASSKEY_AUDIT_LOG=<path>` | Overrides audit log path (defaults to `<data_dir>/audit.log`). |
| `PASSKEY_DISABLE_LACONTEXT=1` | Skips macOS `LocalAuthentication.framework` Touch ID dialog and falls back to `sudo -v`. |
| `PASSKEY_PLUGIN_<CLI>=<entry>` | Session-scoped entry override for `passkey plugin run <cli>` (e.g., `PASSKEY_PLUGIN_GH=github_work`). |

### Exit Codes

| Exit Code | Meaning |
| :---: | :--- |
| **`0`** | Command succeeded (or child process exited `0`). |
| **`1`** | Operational, validation, missing-entry/field, trust, or biometric-denial error (`PasskeyError`). |
| **`2`** | Interactive TTY required (`InteractiveRequiredError` when `--no-input` or headless agent detected), CLI `argparse` usage error, or blocked pre-execution hook (`passkey hook check`). |
| **`N`** | On `passkey run`, `passkey exec`, and `passkey plugin run`, child process exit code `N` is forwarded verbatim (`128 + signum` on signal termination). |

---

## 1. Core Secret Management

| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `passkey` *(bare)* | `[--no-input]` | Context-aware router: offers 1-step MCP migration if exposed configs exist, FTUE onboarding if 0 entries, or fuzzy entry picker if entries exist. |
| `passkey <entry>` | `[--no-input]` | Shortcut for `passkey get <entry>` (opens interactive fuzzy field picker). |
| `passkey new` | `[name] [-t\|--template <tpl>]` | Create a new secret entry via masked interactive input. |
| `passkey request` | `<entry> -f\|--fields <VAR...> [--policy allow\|session\|prompt] [--hint <str>] [--reason <str>] [--timeout 5..300] [--overwrite] [--json]` | Capture or rotate secrets via out-of-band native OS hidden dialog (`osascript` / `zenity`) with popup cooldown rate-limiting. |
| `passkey get` | `[entry] [-a\|--all]` | Interactive field picker (copies 1 field to clipboard for 30s; `--all` copies `KEY='value'` lines). |
| `passkey list` | `[-n\|--names-only] [--json]` | List saved entries (`--json` emits secret-free metadata array). |
| `passkey find` | `[vars...] [--from-file <path>] [--json]` | Reverse-lookup which entry owns given env var name(s) across exact keys and service aliases. |
| `passkey edit` | `[entry]` | Interactive editor to add/modify/remove fields, edit `config`, or rename an entry. |
| `passkey delete` | `<entry> [-y\|--yes]` | Delete an entry from the OS keychain (`--yes` skips confirmation). |
| `passkey info` | `[entry] [--json]` | Show entry metadata, `policy`, `has_active_lease`, `will_prompt_biometric`, `fields`, and `config_keys`. |
| `passkey entry` | `<subcommand>` | Noun-verb group exposing `new`, `request`, `get`, `list`, `find`, `edit`, `delete`, `info`, `clone`, `set-field`, `rotate`, `check`, `template`, and `generate`. |

### Advanced `passkey entry` Subcommands (and Top-Level Aliases)

Every subcommand below can be invoked either as `passkey entry <subcommand>` or directly as a top-level alias `passkey <subcommand>`:

| Command / Alias | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `passkey [entry] clone` | `<source> [dest] [--fields <F...>]` | Clone an entry under a new name, preserving `policy`. |
| `passkey [entry] set-field` | `<entry> <field>` | Upsert a single secret field via masked prompt without touching other fields. |
| `passkey [entry] rotate` | `<entry> [field] [--touch-only]` | Prompt for a rotated field value and update `last_rotated` (`--touch-only` updates timestamp headlessly). |
| `passkey [entry] check` | `<entry> <fields...> [-q\|--quiet] [--json]` | Verify required fields exist on `<entry>` (exits `0` if all present, `1` if missing). |
| `passkey [entry] generate` | `[--length 32] [--no-copy]` | Generate a random secret (copies to clipboard with 30s auto-clear unless `--no-copy`). |
| `passkey [entry] template` | `list \| show <name> \| apply <tpl> [entry] \| add` | List, inspect, apply, or save reusable secret field templates. |

---

## 2. Run & Inject

| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `passkey run` | `[-q\|--quiet] [--strict] [--dry-run [--json]] [--no-masking] [--env-file <path>] <entries...> -- <cmd>` | Inject keychain entries (and optional `passkey://` env files) into `<cmd>` with `stdout`/`stderr` masking. |
| `passkey exec` | `[-q\|--quiet] [--no-strict] [--dry-run [--json]] [--no-masking] [--project-dir <dir>] -- <cmd>` | Auto-discover `.env.passkey` / `.passkey.toml` up to `.git` root, verify HMAC repo trust, and run `<cmd>` with masking. |
| `passkey project init` | `[--from-file <tpl>] [--project-dir <dir>] [--entries <E...>] [-f\|--force] [--no-trust] [--json]` | Scan `.env.example` / `.env.template` and generate committable `.env.passkey` / `.passkey.toml`. |
| `passkey project status` | `[--project-dir <dir>] [--json]` | Inspect manifest discovery, SHA-256 HMAC trust, lease readiness, and missing vars. |
| `passkey project trust` | `[--project-dir <dir>] [--revoke] [--json]` | Approve (or `--revoke`) HMAC trust for a repository's secret manifest. |
| `passkey inject` | `-i\|--in-file <tpl> [-o\|--out-file <out>] [--stdout] [-f\|--force] [--force-git-exposed]` | Render `{{ passkey://entry/field }}` placeholders atomically to a `0o600` gitignored file. |
| `passkey mount` | `<entries...> [--path .env] [--once] [--max-reads <N>] [--timeout <sec>] [--force-git-exposed] [-q\|--quiet]` | Stream secrets through an ephemeral `0o600` POSIX FIFO named pipe that unlinks on exit. |
| `passkey plugin list` | `[--json]` | List all 10 built-in CLI wrapper plugins, resolved entries, scopes, and `entry_exists`. |
| `passkey plugin init` | `<cli> [--entry <name>] [--scope global\|dir\|session]` | Bind a CLI (`claude`, `codex`, `openai`, `gemini`, `cursor-agent`, `gh`, `aws`, `wrangler`, `vercel`, `stripe`) to an entry. |
| `passkey plugin run` | `<cli> [--entry <name>] [--no-masking] -- [args...]` | Execute a bound CLI with credential alias mapping and masked output streams. |
| `passkey browser-fill` | `<entry> --cdp-url <ws://127.0.0.1:PORT[/...]> ` | Verify exact `ORIGIN` over loopback Chrome DevTools WebSocket and autofill login fields/cookies. |

---

## 3. MCP & AI Guardrails

*(Note: `init`, `status`, `doctor`, `servers`, `add`, and `unwrap` work both at top level and under `passkey mcp <subcommand>`.)*

| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `passkey [mcp] init` | `[--tool <name>] [--config <path>] [--dry-run] [--force] [--include-all] [--backup <path>] [-y\|--yes]` | Migrate plaintext MCP server env secrets into OS keychain and wrap configs (`0o600` backup in `<data_dir>/backups/`). |
| `passkey [mcp] status` | `[--tool <name>] [--json]` | Report `secured`, `exposed`, `partial`, or `no_secrets` status across all detected AI tools. |
| `passkey [mcp] doctor` | `[--deep] [--json]` | Run keychain, `PATH`, MCP config, backup, rotation age (`--deep`), and audit integrity (`--deep`) checks. |
| `passkey [mcp] servers` | `[--tool <name>] [--json]` | List configured MCP servers across detected AI clients. |
| `passkey [mcp] add` | `<server> [--tool <name>] [--fields <F...>]` | Add or update keychain credentials for an MCP server interactively. |
| `passkey [mcp] unwrap` | `[--tool <name>] [--server <srv>] [--config <path>] [--restore-secrets] [--dry-run]` | Unwrap `passkey run` MCP configs back to original inline commands. |
| `passkey mcp-serve` | *(none)* | Start the FastMCP stdio server (same entrypoint as `passkey-mcp-server`). |
| `passkey hook install` | `--tool claude\|cursor\|gemini\|all [--project-dir <dir>] [--with-skill]` | Non-destructively install pre-execution secret-protection hooks (and optional skill files). |
| `passkey hook check` | `[--tool claude\|cursor\|gemini]` | Evaluate a hook JSON payload from `stdin` (exits `0` if allowed, `2` if blocked). |
| `passkey skill install` | `[--tool claude\|cursor\|gemini\|agents\|all] [--project-dir <dir>] [--json]` | Install golden-rule `SKILL.md` / `.mdc` / `AGENTS.md` instructions for AI agents. |
| `passkey audit` | `[--limit 10] [--summary] [--verify] [--clear [-y\|--yes]] [--json]` | Inspect, summarize (30-day), clear, or HMAC-verify `<data_dir>/audit.log`. |
| `passkey policy` | `<entry> [allow\|session\|prompt] [--json]` | View or set an entry's biometric access policy. |
| `passkey lease grant` | `<entry> [--ttl 15m] [--max-uses <N>]` | Grant an HMAC-signed temporary lease after OS biometric/passcode auth. |
| `passkey lease list` | `[--json]` | List active leases visible to the current caller. |
| `passkey lease revoke` | `[entry] [--all]` | Revoke a specific entry's lease(s) or `--all` active leases. |

---

## 4. Portability, Config & Utility Commands

| Command | Flags & Arguments | Description |
| :--- | :--- | :--- |
| `passkey export` | `<file> [--entries <E...>] [--no-secrets] [--encrypt]` | Export entries to `0o600` JSON or an `AES-256-GCM` + `Scrypt` encrypted bundle (`--encrypt`). |
| `passkey import` | `<file> [--mode auto\|passkey\|csv\|chrome] [--decrypt] [--dry-run] [--filter <prefix>] [--insecure]` | Import entries from JSON, encrypted bundle (`--decrypt`), CSV, or Chrome export. |
| `passkey share` | `<entry> [-o\|--output <file>] [--shared-by <name>]` | Encrypt a single entry for a teammate with an auto-generated 8-word passphrase. |
| `passkey receive` | `<file>` | Decrypt and import a shared `.enc` entry bundle into the OS keychain. |
| `passkey config` | `[key] [value] [--json]` | View or update settings in `<data_dir>/settings.json`. |
| `passkey completion` | `[--bash \| --zsh \| --fish]` | Print shell tab-completion script (or setup instructions if no flag given). |
| `passkey help` | `[command...]` | Show help for `passkey` or any nested subcommand (e.g., `passkey help project init`). |
| `passkey version` | *(none)* | Print `passkey <version>` and exit. |

### `passkey config` Settings Keys

| Setting Key | Type | Default | Description |
| :--- | :--- | :---: | :--- |
| `require-auth` | `bool` | `false` | Require OS auth (`LAContext` / `sudo` / `pkexec`) before interactive terminal commands. |
| `mcp-write-tools` | `bool` | `true` | Allow mutating MCP tools (`passkey_request_secret`, `passkey_wrap_server`). |
| `mcp-browser-broker` | `bool` | `false` | Enable opt-in `passkey_cdp_autofill` MCP tool over loopback Chrome DevTools. |
| `agent-session-lease-ttl` | `int` / TTL | `600` (`10m`) | Session lease duration (`1s`..`7d`, accepts durations like `5m`, `1h`, or seconds) for `policy = session`. |

---

[← Browser Agent Autofill](07-Browser-Agent-Autofill.md) · [Next: MCP Tools & Prompts Reference →](09-MCP-Tools-and-Prompts-Reference.md)
