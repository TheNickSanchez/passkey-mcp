# Changelog

> **Version scheme reset (2026-07-28):** a senior code review found the 1.x
> labels were not earned (test suite cannot run to completion, auth layer
> breaks headless MCP flows on stock macOS, no CI). Versions were re-baselined:
> `1.0.0 → 0.0.1`, `1.1.0 → 0.1.0`, `1.2.0 → 0.2.0`. See `PLAN.md` for the
> roadmap to a real 1.0. First installable tag will be **0.4.0**.

## [Unreleased]

### Changed

- PLAN current-state describes `main` at 0.3.5 (Protect Main on, D2 prep
  landed; leftover is required check `audit` and D2 publish).
- SECURITY.md points InfoSec at protected `main` and private
  vulnerability reporting as on, not as D0-5 leftovers.
- README shows how wrapping works (config → `passkey run` → OS keychain →
  child env) and states that install does not scan editor configs.

## 0.3.5 (2026-09-14)

### Added

- Trusted Publishing workflow builds wheel and sdist when a GitHub Release
  is published; PyPI stays unpublished until the 0.4.0 tag.
- Dependabot weekly PRs for uv and GitHub Actions (`mcp` stays `<2.0.0`).

### Changed

- `passkey --version` reads package metadata, so a `pyproject.toml` bump is
  the only version edit.
- Packaging metadata lists Python 3.13/3.14 and Issues/Source/PyPI URLs;
  status stays Alpha and unpublished.
- PLAN current-state describes `main` at 0.3.4 (D2 prep is not a 0.4.0
  release).

### Security

- CI runs `pip-audit` against the locked tree so known dependency CVEs
  fail the build. Locked `cryptography` to 50.0.1 (PYSEC-2026-3552).

## 0.3.4 (2026-09-13)

### Changed

- Agent loop: skip sys-arch unless PLAN.md names a design fork; parent chat
  is the PM (no fifth specialist); sys-release promotes the previous
  Unreleased heading on every 0.3.x bump; nits do not restart the four-agent
  cycle.

## 0.3.3 (2026-09-13)

### Added

- CONTRIBUTING.md so contributors have a single entry for setup, tests, and
  the PR loop.

### Changed

- README positions the product as a local OS-keychain injector; install is a
  labeled git preview (PyPI unpublished), Development is `uv` only, and
  `passkey add --fields` is documented as getpass prompts.
- `passkey doctor` recommends the git preview or `uv run passkey` instead of
  `pip install` / PyPI pipx.

### Fixed

- Documented share passphrase entropy as 8 words / ~64 bits (the 0.2.0 notes
  had said 4 words / ~32 bits).

### Security

- Replaced the fake “approved / SOC 2” assessment with a disclosure policy
  and a one-page threat model that matches the code; GitHub Security tab
  file lives at the repo root.

## 0.3.2 (2026-09-13)

### Fixed

- Doctor tests no longer depend on whether Claude/Cursor configs exist on
  the machine. Doctor already stays silent on missing MCP clients; the
  suite now locks that first-run contract so a clean runner is not a
  failed install.
- MCP integration smoke tests mock the OS keyring so Ubuntu CI (no keyring
  daemon) is not a failed install.

### Changed

- CI syncs with `--locked` so a stale lockfile fails the build.

## 0.3.1 (2026-09-12)

### Changed

- Cursor agent profiles (`sys-arch`, `sys-engineer`, `sys-release`,
  `sys-review`), release-hygiene skill, changelog gate on `git push` / `gh pr create`,
  and a PR template that requires SemVer + `[Unreleased]` notes on every branch.
  Dropped leftover Claude Code dir, duplicate ruff config, and stale
  `claude.py` lint ignores. Editor folders (`.vscode/`, `.idea/`) are gitignored.
  Rewrote `AGENTS.md` to match the tree (P0–P3 claims removed).

## 0.3.0 (2026-07-28)

### Changed
- Re-versioned to 0.x; project is pre-1.0 (see note above)
- Deleted stale plans (`PHASE2.md`, `docs/SECURITY_AUDIT_2026.md`); superseded by `PLAN.md`
- Rewrote `AGENTS.md` with verified, accurate workflow instructions

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
  - 256-word built-in passphrase wordlist (~64 bits entropy, 8 words)
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
