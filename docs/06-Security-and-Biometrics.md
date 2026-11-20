[Home](Home.md) › Security & Advanced › **Security & Biometrics**

---

# Security Architecture, Biometrics & Audit Trail

How `passkey-mcp` layers OS keychain ACLs, native macOS Touch ID (`LAContext`), session-bound HMAC leases, stream masking, and tamper-evident audit logging—plus an honest accounting of local OS boundaries.

---

## 1. Threat Model & Honest OS Boundaries

| Threat Vector | Protected? | Mechanism |
| :--- | :---: | :--- |
| Plaintext API keys in `mcp.json`, `.env`, or git history | **Yes** | Credentials live in OS keychain; repos store `passkey://` pointers only; `passkey inject` & `mount` refuse git-exposed paths. |
| Secrets leaking into LLM context via MCP tools or `--json` | **Yes** | All 13 MCP tools and `--json` outputs return entry names, field keys, and status metadata—**never secret values**. |
| Secrets printed to `stdout`/`stderr` by crashes or debug logs | **Yes** | `SecretMasker` scrubs raw UTF-8 and JSON-escaped secret values (`len >= 4`) to `<concealed by passkey>` across pipe chunk boundaries. |
| Secrets exposed in `ps` process `argv` or shell history | **Yes** | CLI never accepts secret values or `pk1:` share tokens on `argv`; interactive input uses masked TTY (`prompt_secret`) / `getpass`, and `passkey request` uses `osascript -` stdin + env attributes. |
| Untrusted repo `.env.passkey` / `.passkey.toml` exfiltration | **Yes** | SHA-256 manifest digest verified against HMAC-signed `trusted_projects.json` (`__trust_hmac_key__` in keychain); requires Touch ID / human approval. |
| Agent editing `leases.json`, `trusted_projects.json`, or `audit.log` | **Yes** | All three stores are authenticated with independent 256-bit HMAC-SHA256 keys stored in the OS keychain (`0o600` on disk). |
| Same-UID malware / root compromise on an unlocked machine | **No (OS boundary)** | Same-UID processes can inspect child `/proc/<pid>/environ` or call `keyring` under the same Python binary ACL on macOS. Use `policy = prompt` / `session` for defense-in-depth. |

### Platform Keychain & Auth Reality

* **macOS (Strongest):** Backed by macOS Login Keychain ACLs + native `LocalAuthentication.framework` (`LAContext` Touch ID / Apple Watch / passcode via `ctypes`, with `sudo -v` fallback). *(Note: for virtualenv/`pipx` installs, macOS Keychain binds the item ACL to the underlying `python3` binary.)*
* **Linux (Best-Effort):** Backed by Freedesktop Secret Service (`gnome-keyring` / `KWallet`); extra OS auth uses `pkexec` (with `sudo` fallback). Requires an unlocked keyring daemon.
* **Windows (Best-Effort):** Backed by Windows Credential Manager ACLs. Extra OS auth (`require-auth` / `prompt`) is a documented no-op because Windows UAC cannot authenticate the current non-elevated process in place.

---

## 2. Per-Entry Access Policies (`allow` vs. `session` vs. `prompt`)

Configure per-entry biometric gating with `passkey policy <entry> [allow|session|prompt]`:

```bash
# Default: headless access (ideal for background MCP servers and low-risk dev keys)
passkey policy resend allow

# Recommended for agentic coding: 1 Touch ID prompt per AI agent / terminal session
passkey policy stripe_dev session

# Maximum lock-down: Touch ID prompt on EVERY access unless an explicit lease is granted
passkey policy aws_prod prompt

# Inspect current policy and active lease status
passkey policy stripe_dev --json
```

| Policy | Headless MCP Startup? | Touch ID Behavior | Best For |
| :--- | :---: | :--- | :--- |
| **`allow`** *(default)* | Yes | Never prompts `LAContext` | Everyday dev API keys & background MCP servers |
| **`session`** | Prompts once | Prompts `"Passkey: unlock '<entry>' for <agent> (10m session)"` on first use, then caches for the calling session | Cloud/staging keys used across multi-turn AI coding sessions |
| **`prompt`** | Requires lease | Prompts Touch ID on **every single invocation** unless a manual `passkey lease grant` is active | Production databases, billing, or root cloud credentials |

### How `policy = session` Prevents PID-Reuse & Cross-Terminal Hijacking

When you approve Touch ID for a `session`-protected entry:
1. `passkey` walks the kernel process tree (`libSystem.proc_pidinfo` `PROC_PIDTBSDINFO` on macOS; `/proc/<pid>/stat` on Linux—zero `/bin/ps` forks, works inside Seatbelt sandboxes) to locate the stable ancestor agent or shell process (`claude`, `cursor`, `gemini`, `codex`, `agy`, or your terminal shell).
2. It mints an HMAC-signed lease in `<data_dir>/leases.json` bound to **`(session_pid, microsecond_process_start_time)`**.
3. Unrelated processes outside that ancestor PID tree cannot see or consume the lease, and if the agent exits and the OS recycles `session_pid`, the microsecond `start_time` mismatch automatically prunes the lease.

Customize the session lease duration (default `600` seconds / `10m`, max `7d`):

```bash
passkey config agent-session-lease-ttl 30m
```

---

## 3. Explicit Time- & Use-Scoped Leases (`passkey lease`)

For strict `policy = prompt` entries, grant temporary, bounded leases from your terminal before kicking off a headless CI/agent task:

```bash
# Grant a 15-minute lease capped at 5 secret injections (prompts Touch ID/OS auth)
passkey lease grant aws_prod --ttl 15m --max-uses 5

# Inspect active leases and remaining uses/seconds
passkey lease list
passkey lease list --json

# Revoke one lease or nuke all active leases immediately
passkey lease revoke aws_prod
passkey lease revoke --all
```

> **Security Note:** Upgrading an entry from `session` to `prompt` immediately ignores any previously auto-minted `session` lease—`prompt` only honors explicit `passkey lease grant` leases.

---

## 4. Global Interactive Terminal Gate (`require-auth`)

Optionally require Touch ID / `sudo` / `pkexec` before interactive terminal commands (`get`, `new`, `edit`, `delete`, `export`, `init`):

```bash
passkey config require-auth on
passkey config --json
```

Global `require-auth` **never** blocks `passkey run` so headless `allow`-policy MCP servers can always launch cleanly.

---

## 5. Tamper-Evident HMAC Audit Log (`passkey audit`)

Every create, read, update, delete, run, lease, policy change, secret request, and browser autofill is appended to `<data_dir>/audit.log` (`0o600`, auto-rotated at ~1 MB):

* **Cryptographic Hash Chain:** Each JSONL record signs `prev_hmac` + canonical record bytes with HMAC-SHA256 (`__audit_hmac_key__` in OS keychain; genesis `prev_hmac = "0" * 64`). Deleting, reordering, or editing any line breaks the chain.
* **Caller Attribution (`actor`):** Records whether the caller was `"human"` or `"agent"` (`claude-code`, `cursor`, `gemini-cli`, `antigravity`, `codex`, `vscode`, etc.) plus its parent PID lineage—while whitelisting `details` keys so secret values can never be logged.

```bash
# View recent operations with caller attribution
passkey audit --limit 20
passkey audit --limit 20 --json

# View 30-day access frequency summary by entry
passkey audit --summary --json

# Cryptographically verify the entire HMAC-SHA256 hash chain (exits 0 if intact, 1 if tampered)
passkey audit --verify
passkey audit --verify --json

# Run extended security diagnostics (entry rotation age + bundle permissions + audit chain)
passkey doctor --deep --json
```

---

[← Team Workflows](05-Team-Workflows.md) · [Next: Browser Agent Autofill →](07-Browser-Agent-Autofill.md)
