[Home](Home.md) › Reference › **Troubleshooting & FAQ**

---

# Troubleshooting & FAQ

Practical fixes for common platform, sandbox, FIFO, manifest-trust, and MCP issues.

---

## 1. Quick Diagnostic Command

Always start with `passkey doctor`:

```bash
passkey doctor
passkey doctor --deep --json
```

It checks:
1. Whether `passkey` is reachable on `PATH` for GUI apps (Cursor, Claude Desktop, VS Code)
2. OS keychain read/write health
3. Exposed or broken MCP server wrappers across all detected tools
4. Lingering `.backup` files next to MCP configs
5. (`--deep`) Entry rotation age (>90 days), bundle file permissions, and `audit.log` HMAC hash-chain integrity

---

## 2. macOS Seatbelt Sandboxes (`KEYCHAIN_ACCESS_ERROR` / `GUI_UNAVAILABLE`)

**Symptom:** An AI coding agent running inside a strict macOS Seatbelt CLI sandbox (such as Codex CLI, Gemini CLI, or Claude Code sandboxed Bash) receives:
* `"error_code": "KEYCHAIN_ACCESS_ERROR"` (`Error: (-50, 'Unknown Error')`), or
* `"error_code": "GUI_UNAVAILABLE"` when calling `passkey request`.

**Why:** macOS Seatbelt sandboxes block subprocesses from talking to `securityd` (macOS Keychain IPC) and `WindowServer` (`osascript` dialogs).

**Fix:**
* **For discovery & secret capture:** Have the agent call the **MCP tools** (`passkey_find`, `passkey_entry_info`, `passkey_project_status`, `passkey_request_secret`). `passkey-mcp-server` runs as a trusted host MCP child process outside the CLI command sandbox, so Keychain IPC and `osascript` dialogs work seamlessly.
* **For running tests with secrets (`passkey exec` / `passkey run`):** Approve unsandboxed execution for `passkey exec` / `passkey run` in your agent's command allowlist (e.g., prefix-allowing `passkey exec` and `passkey run`).

---

## 3. Linux Headless / SSH Keyring (`SecretService` / `dbus` Errors)

**Symptom:** `Failed to access Keychain` or `No recommended backend was available` on Linux over SSH, WSL, or headless CI.

**Fix:** `keyring` on Linux talks to Freedesktop Secret Service (`gnome-keyring-daemon` or `KWallet`) over D-Bus:

```bash
# Ensure dbus-user-session and gnome-keyring + libsecret are installed (Ubuntu/Debian)
sudo apt-get install -y gnome-keyring libsecret-1-0 dbus-user-session

# Unlock gnome-keyring inside a headless/SSH D-Bus session
eval "$(dbus-launch --sh-syntax)"
eval "$(printf '\n' | gnome-keyring-daemon --unlock)"
```

---

## 4. Stale `.env` FIFO Error on `passkey mount`

**Symptom:** `FIFO already exists at '.env'. Remove stale FIFO first: rm '.env'`

**Why:** A previous `passkey mount` process was `SIGKILL`ed (`kill -9`) before its `finally` handler could unlink the named pipe.

**Fix:**

```bash
rm '.env'
passkey mount stripe --path .env --once --timeout 30
```

> **Tip:** Always pass `--timeout <seconds>` and `--once` (or `--max-reads N`) so `passkey mount` unlinks `.env` automatically even if your app crashes before reading it.

---

## 5. `UNTRUSTED_PROJECT` or `manifest_modified` on `passkey exec`

**Symptom:** `Refusing to auto-inject secrets from manifest_modified manifest...` (`error_code: "UNTRUSTED_PROJECT"`).

**Why:** Either `.env.passkey` / `.passkey.toml` changed since you last approved it, or a new manifest file was added to the repository.

**Fix:** Inspect the diff (`git diff .env.passkey .passkey.toml`), then re-approve trust in your terminal (or approve the Touch ID prompt):

```bash
passkey project status
passkey project trust
```

---

## 6. Recovering / Uninstalling After `passkey init`

**Symptom:** You wrapped MCP configs with `passkey init` and want to revert to standard inline MCP configs—or GUI apps like Claude Desktop can't find `passkey` because `~/.local/bin` isn't in macOS launchd `PATH`.

**Fix A — Fix GUI `PATH` on macOS:**
Ensure `~/.local/bin` is on your login `PATH` (`pipx ensurepath`) and restart Claude Desktop / Cursor.

**Fix B — Unwrap MCP configs cleanly:**

```bash
# Restore original server commands (keeps secrets in keychain)
passkey unwrap

# Or write secret values back into the JSON config files before uninstalling
passkey unwrap --restore-secrets
```

Timestamped `0o600` backups created before every `init` and `unwrap` also live in:
* **macOS:** `~/Library/Application Support/passkey/backups/`
* **Linux:** `~/.config/passkey/backups/`
* **Windows:** `%APPDATA%\passkey\backups\`

---

## 7. Verifying or Resetting `audit.log` Integrity

**Symptom:** `passkey doctor --deep` or `passkey audit --verify` reports an HMAC mismatch.

**Why:** Either `<data_dir>/audit.log` was manually edited/truncated, or `__audit_hmac_key__` in the OS keychain was deleted/regenerated.

```bash
# Inspect exact line number where the hash chain broke
passkey audit --verify --json

# Start a fresh hash-chained audit log if you intentionally reset your keychain
passkey audit --clear --yes
```

---

## FAQ

**Q: If I upgrade `passkey-mcp` via `pipx upgrade passkey-mcp` or `uv tool upgrade passkey-mcp`, do I lose my keys?**
No. Secrets live inside your **OS keychain** (`service="passkey"`) and metadata lives in `<data_dir>`. Upgrading, reinstalling, or switching between `pipx` and `uv tool` preserves every entry, policy, lease, and audit log.

**Q: Can an AI agent read my secrets by running `passkey export -` or `passkey get`?**
No. Both commands fail fast with exit code `2` (`INTERACTIVE_REQUIRED`) when invoked from non-TTY or detected AI agent environments, and `passkey hook check` blocks them before execution even begins.

**Q: Why did `passkey-mcp-server` not show new tools after I upgraded?**
Long-running MCP client hosts (Claude Desktop, Cursor, VS Code) keep the old `passkey-mcp-server` stdio process alive until you reload MCP servers or restart the IDE.

---

[← MCP Tools & Prompts Reference](09-MCP-Tools-and-Prompts-Reference.md) · [Back to Home ↑](Home.md)
