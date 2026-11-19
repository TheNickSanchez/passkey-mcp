[Home](Home.md) › Reference › **MCP Tools & Prompts Reference**

---

# MCP Tools & Prompts Reference

`passkey-mcp-server` (and `passkey mcp-serve`) exposes **13 FastMCP tools** and **3 guided `@mcp.prompt()` playbooks**.

> **Core Security Invariant:** No MCP tool ever returns secret or config **values**. Secret values only flow into child processes at runtime (`passkey exec` / `passkey run`), templates (`passkey inject`), or loopback CDP inputs (`passkey_cdp_autofill`).

---

## 1. Read-Only Discovery & Diagnostic Tools (10 Tools)

All 10 read-only tools carry `ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)` and never trigger Touch ID or decrement active lease uses.

| Tool Name | Parameters | Return Schema Highlights | Purpose |
| :--- | :--- | :--- | :--- |
| **`passkey_list`** | *(none)* | `list[str]` — `["github", "stripe"]` | List all entry names stored in the OS keychain. |
| **`passkey_fields`** | `entry_name: str` | `list[str]` — `["STRIPE_SECRET_KEY"]` | List secret field names on an entry without logging a `read` audit event. |
| **`passkey_entry_info`** | `entry_name: str` | `{exists, name, policy, has_active_lease, lease_seconds_remaining, lease_remaining_uses, will_prompt_biometric, fields, config_keys, field_count, config_count, created, modified, last_rotated, source}` | Inspect complete non-sensitive metadata, Touch ID policy (`allow`\|`session`\|`prompt`), and lease readiness for one entry. |
| **`passkey_find`** | `vars: list[str] \| None = None`, `from_file: str \| None = None` | `{ok, all_found, queried, matches, results, resolved_entries, missing_vars, suggested_run_command}` | Reverse-lookup which entry owns given env vars (or `.env.example` keys) across exact keys and service aliases. Refuses live `.env` files (`SENSITIVE_FILE_REFUSED`). |
| **`passkey_preflight_run`** | `entries: list[str]`, `env_files: list[str] \| None = None`, `command: list[str] \| None = None` | `{ready, entries_requested, entries_found, entries_missing, env_files, env_files_missing, references_checked, references_valid, references_invalid, injected_env_vars, prompt_entries_without_lease, will_prompt_biometric, command, command_executable_found, remediation}` | Dry-run preflight for `passkey run` without spawning a child process. |
| **`passkey_project_status`** | `project_dir: str = "."`, `command: list[str] \| None = None` | `{ok, manifest_found, project_root, manifests, manifest_sha256, trusted, trust_status, ready, entries, env_files, required_vars, missing_required_vars, injected_env_vars, will_prompt_biometric, remediation}` | Auto-discover `.env.passkey` / `.passkey.toml`, verify HMAC trust in `trusted_projects.json`, and preflight repo execution. |
| **`passkey_validate_references`** | `file_path: str` | `{valid, checked, missing, prompt_entries_without_lease, will_prompt_biometric}` | Validate `passkey://<entry>/<field>` URIs inside a template or `.env.passkey` file. |
| **`passkey_status`** | *(none)* | `{servers: [...], summary: {secured, exposed, partial, no_secrets}}` | Audit MCP server configs across Claude, Gemini, VS Code, Cursor, OpenCode, Windsurf, Cline, and Zed. |
| **`passkey_doctor`** | `deep: bool = False` | `{healthy, checks, issues, recommendations}` | Run keychain, `PATH`, MCP config, backup, and (`deep=True`) entry age, bundle permission, and audit hash-chain checks. |
| **`passkey_audit_recent`** | `limit: int = 20` *(max 100)* | `list[{timestamp, operation, entry, success, actor, details}]` | Fetch recent sanitized audit log records with caller attribution (`hmac` key material stripped). |

---

## 2. Mutating & Broker Tools (3 Tools — Policy-Gated)

| Tool Name | Annotations (`ro` / `destr` / `idem` / `open`) | Config Gate | Parameters | Return Schema & Behavior |
| :--- | :---: | :--- | :--- | :--- |
| **`passkey_request_secret`** | `False` / `False` / `True` / `False` | `mcp-write-tools` *(default `on`)* | `entry_name: str`, `fields: list[str]`, `policy: str \| None = None`, `hint: str \| None = None`, `reason: str \| None = None`, `timeout: int = 120`, `overwrite: bool = False` | Opens native macOS/Linux hidden password dialog (`Passkey - Secret Request` or `Passkey - Rotate Secret` with Notification Center banner when `reason` is set), saves directly to keychain, and returns `{ok, status, entry, fields_saved, fields_present, policy, rotated?, last_rotated?}`. |
| **`passkey_wrap_server`** | `False` / `False` / `True` / `False` | `mcp-write-tools` *(default `on`)* | `server_name: str`, `config_paths: list[str] \| None = None` | Rewrites an existing MCP server config to launch via `passkey run --quiet <server> -- ...` once `<server>` exists in the keychain. Returns `{success, configs_updated, configs_skipped, errors}`. |
| **`passkey_cdp_autofill`** | `False` / `False` / `False` / `True` | `mcp-browser-broker` *(default **`off`**)* | `entry_name: str`, `cdp_url: str` | Verifies exact `ORIGIN` match over loopback Chrome DevTools WebSocket (`127.0.0.1` / `localhost`) and injects `USERNAME`/`EMAIL`, `PASSWORD`, and/or `SESSION_COOKIE`. Returns `{filled, origin, fields_injected}`. |

### Locking Down Mutating MCP Tools

```bash
# Disable passkey_request_secret and passkey_wrap_server (strictly read-only MCP server)
passkey config mcp-write-tools off

# Enable opt-in Chrome DevTools browser autofill tool
passkey config mcp-browser-broker on
```

> **Security Note:** Path-accepting MCP tools (`passkey_find`, `passkey_preflight_run`, `passkey_project_status`, `passkey_validate_references`, `passkey_wrap_server`) enforce `_is_forbidden_system_path`, blocking `/etc`, `/private/etc`, `/var/root`, `/private/var`, `/System`, `/proc`, `/sys`, `/dev`, `/bin`, `/sbin`, and `/usr`.

---

## 3. Built-In MCP Prompts (`@mcp.prompt()`)

AI clients that support MCP slash prompts (Claude Desktop, Claude Code, Cursor, Zed) can invoke three guided workflows directly:

| Prompt Name | Arguments | Guided Workflow |
| :--- | :--- | :--- |
| **`setup-project-secrets`** | `project_dir: str = "."` | Inspects `.env.example` / `.env.passkey`, maps variables via `passkey_find`, captures missing keys via `passkey_request_secret(policy='session')`, runs `passkey project init`, preflights, and executes via `passkey exec -q -- <cmd>`. |
| **`debug-missing-credential`** | `entry_name: str`, `command: str = ""` | Runs `passkey_entry_info` + `passkey_find` to diagnose missing entries, missing fields, or `session`/`prompt` Touch ID blocks, and verifies readiness with `passkey_preflight_run` and `passkey_doctor`. |
| **`migrate-exposed-mcp-configs`** | *(none)* | Runs `passkey_status()` + `passkey_doctor()` to locate exposed plaintext MCP tokens, previews `passkey init --dry-run --tool <tool>`, and guides safe migration. |

---

[← CLI Command Reference](08-CLI-Command-Reference.md) · [Next: Troubleshooting & FAQ →](10-Troubleshooting-and-FAQ.md)
