# passkey-mcp — Agent Notes

Read this before touching anything. It documents **verified reality**, not
aspirations. The roadmap is `PLAN.md`; current version is **0.3.0** (pre-1.0 —
the old 1.x labels were re-baselined, see `CHANGELOG.md`).

## Environment

- **Python**: 3.10+ floor; dev machine runs 3.14 (`uv` manages it)
- **Package manager**: `uv` — never `pip`. `uv sync` creates `.venv/`
- **CLI install**: `pipx install --force -e .` — required after any change you
  want to exercise through the real `passkey` command
- **One-off validation without reinstall**: `uv run passkey <args>` or
  `uv run python -c "from passkey.cli import main; ..."`

## Testing — the truth (verified 2026-07-28)

**The suite does NOT pass as-committed. Do not trust any doc that says it
does.** There is no CI. Three independent problems:

1. **`tests/test_cli.py` hangs forever.** Tests call real `main()` →
   `_require_auth()` → real `sudo -v`. Without a cached sudo timestamp it
   blocks on an interactive prompt. Nothing mocks the auth layer.
   (It "passes" on the maintainer's Mac only because `pam_tid.so` was
   hand-added to `/etc/pam.d/sudo` and Touch ID silently approves.)
2. **`tests/test_bundle.py` takes ~2 minutes.** Production scrypt is
   N=2^20 ≈ 5s/derivation on this machine, and the file does 20+ derivations.
3. **Tests pollute real user state.** Keyring is mocked but `audit.py` and the
   metadata lock are not — test runs write fake rows into the real
   `~/Library/Application Support/passkey/audit.log` (entries named `test`,
   `found`, `existing` are test fixtures, not your activity).

Also: `pytest-timeout` is NOT installed — `uv run pytest --timeout=120`
errors out, despite what old docs say. `ruff` is NOT in the synced venv
(declared under `[project.optional-dependencies] dev`, which `uv sync`
ignores in favor of `[dependency-groups] dev`). Use `uvx ruff check` instead.

### How to actually validate changes today

```bash
# Fast subset — everything EXCEPT cli/bundle hangs-and-slowdowns (~0.5s, 250 tests)
uv run pytest --ignore=tests/test_cli.py --ignore=tests/test_bundle.py -q

# CLI tests: only with auth mocked or sudo cached; run per-file with care
uv run pytest tests/test_cli.py -q        # HANGS without Touch ID/sudo cache

# Bundle tests: green but ~2 min
uv run pytest tests/test_bundle.py -q

# Lint (ruff is not in the venv)
uvx ruff check passkey/ tests/
```

Fixing all of this is **PLAN.md P0** — until it lands, validate with the
fast subset plus targeted runs, and never present a partial run as "all
tests pass".

## The auth landmine (most important design fact)

`passkey/auth.py` gates sensitive commands behind OS auth: `sudo -v` (macOS),
`pkexec` (Linux), `ShellExecuteW runas` (Windows). Consequences:

- **`passkey run` is auth-gated, and `run` is exactly what passkey-wrapped
  MCP servers execute headless.** On stock macOS (no custom PAM), `sudo -v`
  fails without a tty → every wrapped MCP server fails to start. The dev
  machine only works because of hand-configured Touch ID sudo.
- Even where it works, auth rides the 5-minute sudo timestamp cache —
  MCP servers randomly start failing mid-session.
- Windows `ShellExecuteW runas` elevates a *separate* `cmd /c echo` — it
  proves nothing about the current process. Treat it as placeholder.
- `auth.py` has **zero tests**. The redesign is **PLAN.md P1**; don't build
  new features on the current design, and never call auth from tests
  (mock `passkey.cli._require_auth`).

## Common pitfalls

1. **Test in `.venv`, not pipx.** Change code → `uv sync` → run fast subset.
   Only `pipx install --force -e .` after validation.
2. **`ModuleNotFoundError: No module named 'mcp.server.fastmcp'`** — `mcp>=2.0.0`
   got installed. The pin `mcp>=1.0.0,<2.0.0` in `pyproject.toml` is
   load-bearing (`FastMCP` was removed in v2).
3. **After checking out a branch**, the pipx-installed CLI is stale. Either
   `pipx install --force -e .` or use `uv run passkey`.
4. **Two dev-dep declarations exist** with different pins
   (`[project.optional-dependencies] dev` vs `[dependency-groups] dev`).
   Only the latter is synced. Until P0-1 merges them, assume only
   `pytest` + `pytest-mock` are available in the venv.
5. **JSONC configs with URLs break parsing** — the regex comment-stripper in
   `mcp_config.load_config` eats `//` inside strings
   (`"url": "https://…"` → `JSONDecodeError`). Known bug, PLAN.md P2-1.
6. **`cmd_set_field` silently wipes entry `config`/`created`/`source`**
   (rebuilds `Entry` from scratch). Known bug, PLAN.md P2-3. Same class of
   bug in importer overwrite mode (P2-4). Preserve the whole `Entry` when
   touching save paths.
7. **Audit log lies in two ways right now**: creates saved with
   `is_update=True` are logged as "update" (`keychain.save_entry`), and
   `receive` double-logs imports. PLAN.md P2-2/P2-6.
8. **Don't add a third copy** of anything that already exists twice: doctor
   diagnostics live in `mcp_commands.py`, `health.py`, AND `mcp_server.py`;
   permission checks live in `bundle.py` AND `importers.py`. Consolidation
   is PLAN.md P3.

## Security patterns (established, keep them)

- **Secrets never in argv** — prompt via `getpass.getpass()`.
- **Path validation** — block system prefixes for config writes
  (`mcp_server._validate_config_paths`).
- **Error messages** — sanitize user-controlled strings before interpolating
  (`re.sub(r"[^a-zA-Z0-9._\-\s]", "", s)`).
- **Permissions** — 0o600 files / 0o700 dirs; exports use `O_EXCL`.
- **Crypto** — AES-256-GCM, scrypt(N=2^20, r=8, p=1), fresh `os.urandom`
  salt+nonce per operation. Constants live in `bundle.py` — import them,
  never redefine.
- **MCP boundary** — tools expose names/fields/status only, never values.
- **Config writes** — atomic temp-file + `os.replace` (`mcp_config.save_config`).

## Branch workflow

```bash
git checkout -b feature-branch
# ... make changes ...
uv run pytest --ignore=tests/test_cli.py --ignore=tests/test_bundle.py -q
uvx ruff check passkey/ tests/
uv sync                            # if deps changed
git add -A && git commit -m "msg"  # only with explicit user approval
git push -u origin feature-branch
# PR → merge to main → delete branch locally and remotely
```

## Key files

| File | Purpose | Watch out for |
|------|---------|---------------|
| `passkey/cli.py` | CLI entry, argparse, command grouping | 829-line god-file; auth gates; argparse-private help hack |
| `passkey/auth.py` | OS auth gate | Landmine (see above); no tests |
| `passkey/keychain.py` | OS keychain via `keyring`, PID lock | Audit create/update mislabel; lock needs data dir |
| `passkey/models.py` | `Entry` dataclass, name validation | Clean — `__post_init__` raises `ValueError` (importers must catch) |
| `passkey/bundle.py` | Encrypted export/import, crypto constants | Solid; scrypt params make tests slow |
| `passkey/sharing.py` | Share/receive UX, passphrase gen | Double-log bug; dead expression at ~line 266 |
| `passkey/mcp_config.py` | 9-tool config adapters, atomic save | JSONC URL bug; three doctor forks |
| `passkey/mcp_commands.py` | init/status/doctor/servers/add handlers | `sys.exit` deep in handlers |
| `passkey/mcp_server.py` | MCP server (FastMCP) | Never expose values; `passkey_status` perf loop |
| `passkey/commands.py` | Entry CRUD handlers | `cmd_set_field` data loss |
| `passkey/importers.py` | passkey/MCP/Chrome CSV import | Overwrite drops config |
| `passkey/runner.py` | Env injection for `passkey run` | `sys.exit` in library code |
| `passkey/interactive.py` | questionary selectors | `sys.exit` in library code |
| `passkey/health.py` | rotate, doctor --deep, audit summary | Dead code; "30 days" label doesn't filter |
| `passkey/audit.py` | Audit log | Unbounded; polluted by tests |
| `passkey/clipboard.py` | Auto-clearing clipboard | Clean |
| `passkey/templates.py` | Built-in + custom templates | Clean |
| `passkey/dirs.py` | Data dir resolution, legacy migration | Needs `PASSKEY_DATA_DIR` override (P0-2) |
| `PLAN.md` | Roadmap to 1.0 (P0–P3) | Source of truth for what to work on |
| `tests/` | 282 tests (pytest) | Does not pass as-committed — see Testing |
