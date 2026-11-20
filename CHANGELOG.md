# Changelog

> **Version scheme reset (2026-07-28):** a senior code review found the 1.x
> labels were not earned (test suite cannot run to completion, auth layer
> breaks headless MCP flows on stock macOS, no CI). Versions were re-baselined:
> `1.0.0 → 0.0.1`, `1.1.0 → 0.1.0`, `1.2.0 → 0.2.0`. See `PLAN.md` for the
> roadmap to a real 1.0. First installable tag is **0.4.0**.

## [Unreleased]

## 0.9.1 (2026-11-20)

### Changed

- **Secret-free `entries.json` v2 metadata index**: stores non-sensitive entry metadata (secret and config key names, policy, timestamps, and source — never secret or config values) at `0o600` so metadata queries stay instant and prompt-free, with transparent lazy hydration for legacy v1 indexes.
- **macOS Keychain ACL troubleshooting guide**: documented `Always Allow` vs single-run `Allow` dialogs and `uv tool install --python <version> passkey-mcp` interpreter pinning so Homebrew Python upgrades do not rotate binary code signatures and re-trigger Keychain prompts.

### Fixed

- **Zero-Keychain discovery, preflight & diagnostics**: read-only CLI commands (`list`, `info`, `check`, `find`, `policy <entry>`, `export --no-secrets`, `run --dry-run`, `project status`, `status`, `doctor`, `audit --summary`, `lease list`), shell tab-completion, and MCP discovery/preflight tools now read from the `entries.json` metadata index without triggering OS Keychain access prompts.

### Security

- **Authoritative Keychain policy enforcement & self-healing index**: policy-gated secret-release paths (`run`, `exec`, `inject`, `mount`, `plugin run`, `browser-fill`) hydrate from the OS Keychain and enforce the Keychain payload's authoritative `policy` via `authorize_entry_access` (preventing disk edits to `entries.json` from downgrading `prompt` or `session` protection and automatically repairing drifted metadata), and interactive secret readers (`get`, `export`, `share`) likewise read payloads directly from the OS Keychain rather than `entries.json`.

## 0.9.0 (2026-11-20)

### Added

- **Inline encrypted token sharing (`passkey share`, `passkey upload`, `pk1:` format)**: share full entries or selective fields (`--fields` / positional field names) without touching disk via compact URL-safe `pk1:` tokens authenticated with `AES-256-GCM` (`"pk1:" + header` AAD) + `Scrypt` (`N=2^20, r=8, p=1`), optional `zlib` compression, `120s` clipboard auto-clear, and a random 8-word passphrase (`--no-passphrase` embeds a 256-bit key; `--prompt-passphrase` accepts a custom secret; `-o`/`--output` preserves `PK01` `.enc` file mode).
- **`passkey upload` & upgraded `passkey receive` alias**: import pasted `pk1:` tokens or `.enc` bundles interactively with masked prompts, space/newline/case-tolerant 8-word passphrase normalization, pre-save field-name previews, `--as <name>` renaming, and `--mode ask|skip|overwrite|merge` collision handling.
- **v0.9 architecture & implementation plan (`docs/plans/v0.9-sharing-and-windows.md`)**: documented the 5-phase engineering specification for inline encrypted token sharing (`passkey share` / `passkey upload` `pk1:` format) and first-class Windows parity (`WinVaultKeyring` chunking, `credui.dll` native prompts, Win32 process lineage, PowerShell wrappers, and Windows CI).

### Changed

- **Paste-burst input coalescing in `prompt_secret`**: batches pending terminal paste bytes (`select` / `msvcrt.kbhit`) before redrawing masked `•` bullets so multi-hundred-character `pk1:` tokens paste cleanly in a single render pass.
- **Permanent 6-step release gate (`AGENTS.md`)**: codified mandatory version/lockfile sync, `CHANGELOG.md` promotion, full CLI/MCP/Wiki documentation parity, unpinned install strings, wheel build + global install smoke verification, and annotated `vX.Y.Z` tag + Wiki sync output for every `0.x.0` and `0.x.y` release.

### Security

- **Agent hook & `argv` guards for peer sharing**: `passkey hook check` blocks AI agents from running interactive peer-sharing commands (`passkey share`, `passkey upload`, `passkey receive`, and `passkey entry` equivalents), and CLI invocations refuse `pk1:` tokens passed on the command line so ciphertext/embedded-key tokens never enter process `argv`.

## 0.8.1 (2026-11-19)

### Added

- **Comprehensive multi-page Wiki (`docs/`) & link integrity suite (`tests/test_docs_links.py`)**: added `docs/_Sidebar.md`, `docs/Home.md`, and 10 guides (`01-Quickstart.md` through `10-Troubleshooting-and-FAQ.md`) covering human workflows, zero-config `passkey exec`, AI agent onboarding, `session` Touch ID policies, CDP browser autofill, and full CLI/MCP references, verified automatically against `parser.py` and `mcp_server.py`.

### Changed

- Revamped `README.md` with a concise before/after `mcp.json` diff, visual feature showcases (`SecretMasker`, `passkey request`, `policy = session`, `passkey exec`), ASCII security boundary diagram, and Wiki navigation hub.
- Unpinned PyPI install recommendations (`uv tool install passkey-mcp` / `pipx install passkey-mcp`) across `README.md`, `docs/`, `SECURITY.md`, and `passkey doctor`, and retired Landmine #8 in `AGENTS.md` now that `0.8.0` is live on PyPI with digital provenance attestations.

### Fixed

- Passed `GH_REPO: ${{ github.repository }}` to `gh release upload` in `.github/workflows/release.yml` so the checkout-free `publish` job attaches wheel and sdist artifacts cleanly to GitHub Releases.

## 0.8.0 (2026-11-19)

### Added

- **Structured error codes & `PASSKEY_OUTPUT=json` envelopes**: `PasskeyError` and `InteractiveRequiredError` now carry structured `error_code`, `entry`, `missing_fields`, and `remediation_command` metadata, emitting deterministic `{"ok": false, "error_code": ..., ...}` JSON envelopes whenever `--json` or `PASSKEY_OUTPUT=json` is active (routing to `stderr` on child-wrapping commands `run`, `exec`, and `plugin run` so child `stdout` pipelines stay pristine).
- **Reverse env-var lookup (`passkey find` & MCP `passkey_find`)**: locate which keychain entry owns one or more environment variables (`passkey find RESEND_API_KEY GH_TOKEN --json` or `passkey find --from-file .env.example --json`) via 3-tier matching across exact keys, service-specific aliases, and entry-scoped generic names without reading or exposing secret values.
- **Zero-config repo manifests, HMAC trust guard & `passkey exec` (`passkey/project.py`)**: added `passkey project init|status|trust`, `passkey exec -- <command>`, and MCP `passkey_project_status` to auto-discover `.env.passkey` / `.passkey.toml` up to the enclosing git root, verify SHA-256 digests against HMAC-signed `<data_dir>/trusted_projects.json` (`__trust_hmac_key__`), prompt Touch ID once on untrusted/modified manifests, and inject secrets with `SecretMasker` enabled.
- **Session-scoped Touch ID policy (`policy = session`)**: added `"session"` alongside `"allow"` and `"prompt"`, prompting Touch ID once per AI agent or terminal session (`"Passkey: unlock '<entry>' for <agent> (10m session)"`) and minting an HMAC-signed lease bound to `(ancestor_pid, process_start_time)` (configurable via `passkey config agent-session-lease-ttl`, default `600s`), while keeping `policy = prompt` strictly per-invocation.
- **Out-of-band native OS secret capture & rotation (`passkey request` & MCP `passkey_request_secret`)**: agents can trigger a native OS hidden password dialog (`osascript -` StandardAdditions `display dialog ... with hidden answer` via 7-bit ASCII `system attribute` env vars on macOS; `zenity --password` on Linux) that saves secrets directly into the OS keychain and returns only field metadata, with `--reason` expired-token Notification Center alerts (`Passkey - Rotate Secret` + automatic `last_rotated` stamping), idempotent field merging, and popup cooldown rate-limiting.
- **Multi-tool hook onboarding (`passkey hook install --tool all`) & `ANTIGRAVITY_AGENT` detection**: added `--tool all` to `passkey hook install` (pairing with `--with-skill`) and registered `ANTIGRAVITY_AGENT` in `_HEADLESS_AGENT_ENV_VARS` / `_AGENT_ENV_MARKERS`.

### Security

- **Seatbelt-compatible kernel process lineage (`proc_pidinfo` / `/proc/<pid>/stat`)**: replaced `/bin/ps` subprocess calls in `passkey/audit.py` with direct `libSystem.proc_pidinfo` (`PROC_PIDTBSDINFO`) on macOS and `/proc/<pid>/stat` on Linux, eliminating restricted-binary failures inside macOS Seatbelt sandboxes and providing microsecond-resolution start timestamps for PID-reuse defense.
- **Keychain-vs-tampering error precision & MCP directory path blocking**: `trusted_projects.json` and `leases.json` now raise `KeychainAccessError` (`KEYCHAIN_ACCESS_ERROR`) instead of minting a mismatched fallback key when Keychain IPC is blocked (e.g., macOS Seatbelt `-50`), and `_is_forbidden_system_path` blocks bare protected system directories (`/etc`) alongside file paths (`/etc/passwd`).

## 0.7.0 (2026-11-18)

### Added

- **Non-TTY & PTY AI agent fail-fast (`--no-input`, exit code `2`)**: interactive commands (`passkey`, `new`, `edit`, `get`, `delete`, `set-field`, `rotate`, `init`, `add`, `share`, `receive`, `export --encrypt`, `import --decrypt`, `audit --clear`, `template apply|add`, and positional `passkey <entry>`) now fail fast with exit code `2` and actionable remediation hints when `--no-input` is set, stdin/stdout is not a TTY, or a headless AI agent environment variable (`CLAUDECODE`, `CURSOR_AGENT`, `GEMINI_CLI`, `CODEX_ENV`, `OPENAI_CODEX`, `AIDER`) is detected (`PASSKEY_ALLOW_INTERACTIVE=1` overrides).
- **Headless confirmation & rotation flags (`--yes`, `--touch-only`)**: added `-y`/`--yes` to `passkey delete`, `passkey init`, and `passkey audit --clear`, and `--touch-only` to `passkey rotate`.
- **Deterministic secret-free `--json` across CLI read & diagnostic commands**: added `--json` to `list`, `info`, `check`, `doctor`, `audit` (including `--summary` and `--verify`), `lease list`, `plugin list` (with `entry_exists`), `policy`, `config`, and `skill install`, and ensured empty `status --json` and `servers --json` emit `[]` instead of human text.
- **Preflight `passkey run --dry-run [--json]` & `--strict`**: validates entries, `--env-file` mappings, `passkey://` references, `prompt` policy / active leases (`peek_lease`), and target command executables without spawning a child process or exposing secret values; `--strict` exits `1` immediately when any requested entry is missing.
- **Richer MCP discovery, preflight & prompts (`passkey/mcp_server.py`)**: added `passkey_entry_info` and `passkey_preflight_run`, enriched `passkey_validate_references` with `prompt_entries_without_lease` and `will_prompt_biometric`, added `FastMCP` server `instructions`, `ToolAnnotations` (`readOnlyHint` / `destructiveHint`) on all 10 tools, and 3 `@mcp.prompt()` workflows (`setup-project-secrets`, `debug-missing-credential`, `migrate-exposed-mcp-configs`).
- **Agent skill & rules installer (`passkey/skills.py`)**: added `passkey skill install --tool claude|cursor|gemini|agents|all` and `passkey hook install --with-skill` to atomically install concise golden-rule instructions into `.claude/skills/passkey/SKILL.md`, `.cursor/rules/passkey.mdc`, `.gemini/skills/passkey/SKILL.md`, and bounded `AGENTS.md` markers.
- **Bounded `passkey mount --timeout` & stale-FIFO diagnostics**: added `--timeout <seconds>` (non-blocking `O_WRONLY | O_NONBLOCK` polling without `signal.alarm`), fast-fail guard for unbounded headless `mount`, and specific `rm '<path>'` guidance when a stale FIFO exists.

### Changed

- **Lazy `FastMCP` import & read-only lease inspection**: `passkey.cli` now lazy-imports `passkey.mcp_server` only on `mcp-serve` (avoiding startup overhead and `.env` FIFO consumption by `FastMCP`'s Pydantic BaseSettings), and `peek_lease()` / `peek_all_leases()` inspect active leases without decrementing `remaining_uses` or writing `read` audit entries during metadata checks.
- **Actionable agent remediation hints & banner suppression**: missing entry/field errors across `runner`, `references`, `commands`, `hooks`, and `mcp_server` instruct agents to ask the human user to run `passkey new <entry>` or `passkey lease grant <entry> --ttl 15m` rather than pasting secrets in chat, and `passkey run` automatically suppresses the multi-line `SECURITY WARNING` banner inside detected AI agent subprocesses.

### Security

- **Hardened `passkey hook check` & `passkey inject` git-exposure guard**: pre-execution hooks now strip `--no-input` before subcommand matching and additionally block `passkey get` / `entry get`, `passkey generate --no-copy`, and `passkey inject --stdout` / `-o -`; `passkey inject` refuses writing to non-gitignored paths inside git repositories unless `--force-git-exposed` is passed.

### Fixed

- `passkey rotate` and non-interactive `edit` no longer stamp `last_rotated` or re-save unchanged entries when `prompt_secret` raises `EOFError` or receives empty input.

## 0.6.0 (2026-11-18)

### Added

- **Real-time masked secret input (`prompt_secret`)**: `passkey new`, `edit`, `set-field`, `rotate`, and `add` now echo `•` bullets alongside a live character counter, with `Backspace`/`Delete`, `Ctrl+U` clear, and `Ctrl+R`/`Tab` temporary reveal (auto-remasked on `Enter` so terminal scrollback never retains secrets).
- **Noun-verb subcommand groups (`passkey mcp`, `passkey entry`) and `help` / `version` subcommands**: organized MCP and advanced entry commands under scannable hierarchies, added `passkey help [command]` and `passkey version` (`-V`) alongside `-h`/`--help`/`--version`, and preserved all existing top-level commands as backwards-compatible aliases.
- **Positional name, `--template`, and `KEY=VALUE` shorthand in `passkey new`**: run `passkey new stripe` (or `--template <name>`) to jump straight to field entry, paste `KEY=VALUE` at the field prompt in a single step, verify lengths via non-sensitive previews (`(36 chars, sk-…9a2)`), and press `Enter` on an empty field name to save and exit.

### Changed

- **Categorized `passkey --help` output**: replaced the 34-command flat dump and 22-line epilog with four `gh`-style groups (`Core Secret Management`, `Run & Inject`, `MCP & AI Guardrails`, `Portability & Config`) and 7 high-signal examples while hiding internal plumbing (`mcp-serve`) and secondary aliases.
- **Context-aware bare `passkey` FTUE & `passkey get` picker**: bare `passkey` now detects exposed MCP server credentials for 1-step keychain migration (State A), offers quickstart onboarding on clean machines (State B), or opens the fuzzy entry browser when entries exist (State C), auto-copying 1-field entries immediately and using an arrow-key filterable field picker for multi-field entries.
- **Clearer `passkey init` pre-flight preview**: displays per-server masked secret previews, inline non-secret env vars, the `0o600` `<data_dir>/backups/` location, and the exact `passkey unwrap` rollback command before modifying any config file.

## 0.5.0 (2026-11-18)

### Added

- **Real-time `stdout`/`stderr` secret masking** (`passkey/masking.py`): `passkey run` and `passkey plugin run` scrub injected secret values (`len >= 4`, raw UTF-8 and JSON-escaped variants, across OS chunk boundaries) with `<concealed by passkey>`. Added `--no-masking` and `-q`/`--quiet` to `passkey run`.
- **Structured secret reference URIs & template injection** (`passkey/references.py`): `passkey://<entry>/<field>` with `$VAR`/`${VAR}` interpolation strictly inside `<entry>`, `passkey run --env-file`, `passkey inject`, and `passkey_validate_references` MCP tool.
- **Ephemeral POSIX FIFO `.env` mounts** (`passkey/mount.py`): `passkey mount` streams secrets through a `0o600` named pipe that refuses git-tracked non-ignored paths and unlinks on exit/`SIGINT`/`SIGTERM`.
- **Pre-execution AI agent hooks** (`passkey/hooks.py`): `passkey hook install --tool claude|cursor|gemini` and `passkey hook check` block agent file/shell reads of `.env`, `*.backup`, `*.enc`, and plaintext `passkey export`.
- **Tamper-evident HMAC-SHA256 audit chain & caller attribution** (`passkey/audit.py`): `prev_hmac`/`hmac` hash chain keyed by `__audit_hmac_key__` in the OS keychain, parent-PID caller attribution (`actor`), `passkey audit --verify`, `audit_integrity` in `passkey doctor --deep`, and `passkey_audit_recent` MCP tool.
- **Native macOS Touch ID (`LAContext`), entry policies & scoped leases** (`passkey/auth.py`, `passkey/leases.py`): `LocalAuthentication.framework` biometric prompt via `ctypes` (`sudo -v` fallback), `passkey policy <entry> allow|prompt`, and HMAC-signed time/use-scoped `passkey lease grant|list|revoke`.
- **Zero-config CLI plugin wrappers** (`passkey/plugins.py`, `passkey/templates.py`): `passkey plugin init|list|run` and `<data_dir>/plugins.sh` for `claude`, `codex`, `openai`, `gemini`, `cursor-agent`, `gh`, `aws`, `wrangler`, `vercel`, and `stripe`, plus built-in templates.
- **Deterministic CDP browser credential broker** (`passkey/browser_broker.py`): `passkey browser-fill` and opt-in `passkey_cdp_autofill` MCP tool (`mcp-browser-broker`) verify exact `scheme + hostname + port` origin over loopback RFC-6455 WebSocket before injecting `USERNAME`/`EMAIL`/`PASSWORD`/`SESSION_COOKIE`.

### Changed

- `passkey init` wraps servers with `passkey run --quiet ...`, stores `0o600` timestamped backups in `<data_dir>/backups/` instead of adjacent `<config>.backup` files, and accurately reports `"secured"` status for array-command clients (OpenCode).
- `extract_secrets` scans values for embedded URI credentials (`://user:pass@`) and known token prefixes (`ghp_`, `github_pat_`, `sk-`, `xoxb-`, `AKIA`, JWT `eyJ...`) even under generic variable names.

### Security

- Plaintext `passkey export -` requires an interactive TTY (`sys.stdin.isatty()`) and fails closed when piped.
- Removed unused positional `value` argument from `passkey set-field` so secrets cannot enter process `argv`.
- Added `mcp-write-tools` setting to lock down `passkey_wrap_server` (`PLAN.md` D3-4) and expanded MCP path validation to block macOS `/private/etc/` and `/private/var/` symlink targets.
- `passkey doctor` warns on lingering `.backup` files next to MCP configs.
- Updated locked transitive dependencies (`certifi`, `filelock`, `msgpack`, `pyjwt`, `urllib3`) in `uv.lock` to clear `pip-audit` advisories.

### Fixed

- Explicit `PASSKEY_DATA_DIR` overrides no longer auto-migrate files from legacy `~/.passkey`, and `passkey add` preserves existing entry `config`, `created`, `source`, `last_rotated`, and `policy` metadata on update.

## 0.4.3 (2026-09-14)

### Security

- A locked or empty keychain no longer deletes the matching name from
  `entries.json`.
- An existing data directory with group/other bits set is tightened to
  `0o700` on POSIX without following a symlink.

## 0.4.2 (2026-09-14)

### Changed

- `passkey get --all` copies `KEY='value'` env lines (every value
  single-quoted). Interactive `get` still copies a raw field value.

### Fixed

- `passkey get --all` and `passkey generate` keep the copied secret on
  the clipboard for 30 seconds after the CLI exits, instead of wiping
  it immediately via an atexit handler.

## 0.4.1 (2026-09-14)

### Changed

- README and `passkey doctor` recommend `pipx install passkey-mcp==0.4.0`
  (PyPI is live). `uv tool install passkey-mcp` is the uv-native twin.
  Clone development stays `uv run passkey`.
- PLAN current-state describes `main` after D2 publish: tag `v0.4.0`,
  PyPI 0.4.0, Protect Main including `audit`. D2-6 is this pin; D2-7
  MCP smoke and D3-4 / D3-5 stay open.

## 0.4.0 (2026-09-14)

### Changed

- First installable release is 0.4.0: still Alpha, a local OS-keychain
  injector for MCP/CLI secrets, not a team vault. This PR does not tag,
  publish to PyPI, or open a GitHub Release; D2 publish stays open until
  Nick’s Release.
- PLAN current-state describes `main` as 0.4.0 untagged, with Protect Main
  requiring `lint`, the four `test` jobs, and `audit`.
- Dependabot ignores `mcp` semver-major so a range-widening PR (like #7)
  cannot land mcp 2.x (FastMCP was removed in v2).

## 0.3.7 (2026-09-14)

### Changed

- CI and release workflows use `setup-uv` v7, `upload-artifact` v7, and
  `download-artifact` v8 (Dependabot #10–#12, landed together so the
  publish job keeps a matching artifact pair).

## 0.3.6 (2026-09-14)

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
