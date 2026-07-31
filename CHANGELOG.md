# Changelog

> **Version scheme reset (2026-07-28):** a senior code review found the 1.x
> labels were not earned (test suite cannot run to completion, auth layer
> breaks headless MCP flows on stock macOS, no CI). Versions were re-baselined:
> `1.0.0 → 0.0.1`, `1.1.0 → 0.1.0`, `1.2.0 → 0.2.0`. See `PLAN.md` for the
> roadmap to a real 1.0.

## 0.3.0 (2026-07-28)

### Changed
- Re-versioned to 0.x; project is pre-1.0 (see note above)
- Deleted stale plans (`PHASE2.md`, `docs/SECURITY_AUDIT_2026.md`); superseded by `PLAN.md`
- Rewrote `AGENTS.md` with verified, accurate workflow instructions

### Known issues (documented in `PLAN.md`)
- Test suite hangs on real `sudo` prompts and writes to the real data dir — do not trust a green run from a warm-cache machine
- `passkey run` requires OS auth that fails headless on stock macOS, breaking passkey-wrapped MCP servers
- JSONC config parsing corrupts URLs (`https://…`)

## 0.2.0 (2026-07-26, previously "1.2.0")

### Added
- **`passkey generate`** — cryptographically secure random secret generation
  - Guarantees character diversity (uppercase, lowercase, digits, symbols)
  - Configurable length (`--length N`, default 32)
  - Auto-copy to clipboard (disable with `--no-copy`)
  - Integrated into `passkey new` interactive flow ("Generate a secure value?")
- **Credential templates** — pre-built configs for popular services
  - 8 built-in templates: GitHub, AWS, Slack, OpenAI, Stripe, Vercel, PostgreSQL, MySQL
  - `passkey template list|show|apply|add` commands
  - Custom templates saved to `~/.config/passkey/templates/`
  - Secret values stripped when saving custom templates
  - Integrated into `passkey new` flow ("Start from a template?")
- **`passkey share`** — share entries via encrypted file + passphrase
  - 256-word built-in passphrase wordlist (~32 bits entropy, 4 words)
  - Displays passphrase for human relay (no key exchange needed)
  - `shared_by` and `shared_at` metadata tracked in encrypted payload
- **`passkey receive`** — import shared entries by passphrase
  - Decrypts bundle file with passphrase
  - Single-entry or full-bundle import
- **`passkey rotate`** — mark an entry as rotated
  - Updates `last_rotated` timestamp for lifecycle tracking
- **`passkey doctor --deep`** — expanded diagnostics
  - Entry age checks (warns if >90 days without rotation)
  - MCP config security check (warns about plaintext secrets)
  - Bundle file permission check
- **`passkey audit --summary`** — aggregate audit statistics
  - Total operations, operations by type, most accessed entries
  - Oldest entry, oldest rotation, entries never rotated
- `last_rotated` field added to entry metadata (serialized in exports)

### Changed
- `passkey new` now offers generate and template options during creation
- `passkey info` displays `Last Rotated` timestamp when available

## 0.1.0 (2026-07-26, previously "1.1.0")

### Added
- **Tool-agnostic MCP support** — works with Claude, Gemini, VS Code, Cursor, OpenCode, Windsurf, Cline, and Zed
  - Adapter-based architecture (`passkey/mcp_config.py`) with per-tool config paths, root keys, and command formats
  - `passkey init --tool <name>` to migrate configs for any supported tool
  - `passkey status` shows security status across all detected tools
  - `passkey servers` lists MCP servers across all tools
  - `passkey doctor` runs diagnostics on all tool configs
- **Shell tab completion** (`passkey/completion.py`)
  - `passkey completion` shows setup instructions for bash, zsh, and fish
  - `passkey completion --zsh` / `--bash` / `--fish` prints the completion script
  - Entry names complete for all subcommands (`passkey get <TAB>`, `passkey hugg<TAB>`)
  - `passkey list --names-only` for clean one-per-line output
- **OS-level authentication** (`passkey/auth.py`)
  - macOS: uses `sudo -v` (honors Touch ID / PAM config)
  - Linux: PolicyKit dialog via `pkexec`
  - Windows: UAC elevation via `ShellExecuteW`
  - Fallback: `getpass` + `sudo -S` for headless environments
- **Interactive onboarding** for first-time users
  - Welcome banner with feature overview
  - Guided first-entry creation
  - Shell completion setup prompt

### Changed
- `passkey init`, `status`, `doctor`, `servers`, `add` are now top-level commands (not just under `passkey claude`)
- `passkey claude init/status` kept as backward-compatible aliases
- Auth required before all secret read/write operations (new, get, edit, delete, run, export, import, etc.)
- MCP server tools renamed: `passkey_list`, `passkey_fields`, `passkey_status`, `passkey_doctor`, `passkey_wrap_server`
- Improved error messages with actionable suggestions

### Fixed
- Bare `except:` in `importers.py` now catches specific exceptions
- Unused imports removed across codebase
- All exception re-raises now use `from err` / `from None` for proper chaining
- Help text: `--new` → `new`, `--list` → `list` (was confusing)

### Security
- LLMs/agents can discover entry names but never read secret values
- `passkey list --names-only` outputs names only (no accidental value exposure)
- MCP server tools never expose values through the protocol

## 0.0.1 (2026-05-08, previously "1.0.0")

### Added
- Encrypted bundle export/import (`passkey export --encrypt`, `passkey import --decrypt`)
  - AES-256-GCM encryption with scrypt key derivation
  - Portable machine provisioning via passphrase-protected bundles
  - `--setup-claude` flag to auto-configure MCP servers on import
- Entry name validation (alphanumeric + hyphens/underscores/dots, 1-64 chars)
- `--insecure` flag for importing files with insecure permissions
- PID-aware lock file with automatic stale lock cleanup

### Changed
- Atomic config file writes (prevents corruption on crash)
- Improved secret detection heuristics (fewer false positives on `PAGE_ID`, `BOARD_ID`, etc.)
- Stdout export now requires confirmation when secrets are included
- Import refuses world-readable files by default (use `--insecure` to override)

### Removed
- `passkey_add_secret` MCP tool (secrets must not transit through LLM context)
- `passkey_init_server` MCP tool (deprecated, non-functional)

### Security
- Secrets no longer flow through the MCP/LLM channel
- Bundle files created with 0600 permissions
- File-based lock includes PID for stale lock detection
- Config writes use atomic temp-file + rename pattern
