# Passkey v1.0 — Vision & Release Plan

## What passkey is

A **personal password manager for MCP servers and CLI tools** — like 1Password but purpose-built for:
- Developers who use Claude Code, Cursor, VS Code with MCP servers
- Teams that need quick, secure machine provisioning
- Anyone who wants `biometric unlock → env injection → subprocess` without config file secrets

### Core principles

1. **Keychain-native** — macOS Keychain is the vault. Touch ID is the auth. No custom crypto.
2. **Zero network** — no sync servers, no cloud. Secrets stay on-device unless explicitly exported.
3. **MCP-first** — designed around the `command + env` pattern that MCP servers use.
4. **Portable setup** — encrypted bundles let you provision a new machine in one command.
5. **LLM-safe** — the AI can discover *what* secrets exist and *configure* wrappers, but never sees secret *values*.

---

## User stories

| Persona | Story |
|---------|-------|
| Alice (today) | `passkey run myservice -- python mcp_server.py` injects API creds without touching config |
| Bob (teammate) | Installs passkey, imports an encrypted bundle Alice shared, machine is fully configured |
| Future Alice | New MacBook — grabs encrypted bundle from USB, runs `passkey import --decrypt`, 11 MCP servers configured in 60 seconds |

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Claude Code / Cursor / VS Code                  │
│  MCP config: "command": "passkey",               │
│              "args": ["run", "myapi", "--", ...]  │
└──────────────────────┬──────────────────────────┘
                       │ spawn
                       ▼
┌─────────────────────────────────────────────────┐
│  passkey run <entry> -- <cmd> [args...]           │
│  1. Read entry from system keychain              │
│  2. Inject fields as env vars                    │
│  3. Exec child process                           │
└──────────────────────┬──────────────────────────┘
                       │ keyring API
                       ▼
┌─────────────────────────────────────────────────┐
│  System Keychain / Credential Store              │
│  Service: "passkey"                              │
│  Entries: github, slack, myapi, openai, ...      │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  Encrypted bundles (.passkey.enc)                │
│  AES-256-GCM + scrypt key derivation            │
│  passkey export --encrypt / import --decrypt     │
└─────────────────────────────────────────────────┘
```

---

## What shipped in v1.0

### Security hardening
- Removed `passkey_add_secret` from MCP surface (secrets never transit LLM context)
- Removed deprecated `passkey_init_server` MCP tool
- Entry name validation at model layer (prevents injection via reserved/malformed names)
- Atomic config writes via temp file + `os.replace()`
- PID-aware lock file (auto-cleans stale locks from dead processes)
- Fixed false-positive secret detection (`PAGE_ID`, `BOARD_ID` no longer flagged)
- Stdout export requires confirmation
- Import refuses world-readable files without `--insecure`

### Encrypted bundles
- `passkey export --encrypt output.passkey.enc` — portable encrypted export
- `passkey import --decrypt input.passkey.enc` — import with passphrase
- `--setup-claude` flag auto-rewrites MCP config on import
- AES-256-GCM encryption, scrypt key derivation (N=2^20, r=8, p=1)
- Bundle format: `PK01` magic + version + salt + nonce + ciphertext
- 12+ character passphrase requirement

### Packaging
- Renamed to `passkey-mcp` for PyPI (avoids FIDO2/WebAuthn namespace collision)
- Version bumped to 1.0.0
- MIT LICENSE file added
- `.gitignore` configured
- 149 tests passing

---

## Distribution model

**Independent installs.** Each team member:
1. `pip install passkey-mcp` (or `pipx install passkey-mcp`)
2. Creates their own entries: `passkey --new`
3. Configures Claude Code: `passkey claude init` or manual config

**Onboarding flow for teammates:**
1. Alice exports: `passkey export --encrypt --entries github,slack,myapi /tmp/team-setup.enc`
2. Shares bundle via secure transfer (encrypted, safe in transit)
3. Shares passphrase via separate channel
4. Teammate imports: `passkey import --decrypt --setup-claude /tmp/team-setup.enc`
5. Teammate restarts Claude Code — all MCP servers working

---

## What v1.0 does NOT include

- Team vault / shared secrets server
- Sync between machines (use bundles for one-time transfer)
- Windows/Linux support (macOS Keychain only)
- Secret rotation automation
- GUI / menu bar app

---

## Future considerations (v1.x / v2.0)

- **`passkey rotate`** — guided secret rotation with audit trail
- **Selective field export** — export only specific fields from entries
- **macOS concealed pasteboard** — mark clipboard content as sensitive (prevents history tools from capturing)
- **Chained-hash audit log** — tamper-evident operation history
- **`passkey doctor --fix`** — auto-remediate configuration issues
- **Linux `secret-service` backend** — same UX on Linux via GNOME Keyring / KDE Wallet
