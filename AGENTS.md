# passkey-mcp — Agent Notes

Verified 2026-09-12. Roadmap is `PLAN.md` (first installable release **0.4.0**).
Package version lives in `pyproject.toml` (also duplicated in
`passkey/__init__.py` until D2-5). This tree is **0.3.x**, Alpha, unpublished.

Positioning: local OS-keychain injector for MCP/CLI secrets. Not a team vault.

## Agents

Custom profiles in `.cursor/agents/`. Pick one per chat (see
`.cursor/rules/agent-routing.mdc`).

| Profile | Job |
|---------|-----|
| `sys-arch` | Research, `PLAN.md`. No `passkey/` or `tests/` edits. |
| `sys-engineer` | Implement and test. |
| `sys-release` | Every PR: SemVer + `CHANGELOG.md` `[Unreleased]` + version bump. |
| `sys-review` | Read-only pre-PR review. |

Loop: arch (if design is open) → engineer → release → review → PR.
A hook denies `git push` / `gh pr create` if `CHANGELOG.md` is unchanged vs
`main`. Until 1.0: **patch** = fix/docs/tests/CI; **minor** = feature or 0.x
breaking; **major** = 1.0.0 only. First tag is 0.4.0; before that bump 0.3.x.

## Environment

- Python 3.10+; this machine is 3.14. **`uv` only — never pip.**
- `uv sync` creates `.venv/`. Lint config is **`ruff.toml` only**.
- Exercise the CLI with `uv run passkey …` (pipx is stale until D2 / PyPI).

```bash
uv sync
uv run pytest -q
uv run ruff check passkey/ tests/
uv run passkey --help
```

CI exists (`.github/workflows/ci.yml`: macOS + Ubuntu, 3.10 and 3.14). The
only known red test on a clean runner is
`tests/test_mcp_server.py::TestPasskeyDoctor::test_detects_missing_config`
(doctor only iterates configs that already exist). Do not present a partial
run as “all tests pass.” Do not ignore `test_cli.py` / `test_bundle.py` —
those hangs are gone.

## Auth

Primary protection is the OS keychain ACL. Extra sudo/pkexec is **opt-in**
(`passkey config require-auth on`) and **never** applies to `passkey run`
(headless MCP). Windows extra-auth is a documented no-op.

Tests: `tests/conftest.py` sets `PASSKEY_DATA_DIR`, defangs scrypt to 2^14,
and mocks `passkey.cli._require_auth`. Never call real sudo/pkexec. Cover
`auth.py` only via `tests/test_auth.py` (subprocess mocked).

## Landmines

1. `mcp>=1.0.0,<2.0.0` is load-bearing (`FastMCP` removed in v2).
2. Secrets never in argv — `getpass`. Do not add `KEY=VALUE` examples.
3. Preserve the whole `Entry` on save (`config`, `created`, `source`).
4. MCP tools: names/fields/status only — never values.
5. Config writes: atomic temp + `os.replace`. Exports: `O_EXCL`, `0o600`.
6. Crypto constants: import from `bundle.py`, never redefine.
7. Do not add a third doctor or a second permission checker (`doctor.py` and
   `bundle.check_file_permissions` are the singles).
8. `docs/SECURITY.md` currently overclaims (“approved for corporate use”).
   Do not copy that language. README install (`pipx install passkey-mcp`)
   404s until D2. PyPI is unpublished; no tags.
9. After a branch checkout, `uv run passkey` — not a stale global install.

## Key files

| File | Purpose |
|------|---------|
| `PLAN.md` | What to work on (D0–D3 → 0.4.0) |
| `passkey/cli/` | CLI entry (`cli.py` is a shim) |
| `passkey/auth.py` | Opt-in OS prompt only |
| `passkey/keychain.py` | OS keychain + file index `entries.json` |
| `passkey/bundle.py` | AES-256-GCM + scrypt export/import |
| `passkey/mcp_config.py` | Tool adapters, JSONC, atomic save |
| `passkey/mcp_server.py` | FastMCP tools (no secret values) |
| `passkey/doctor.py` | Unified diagnostics |
| `passkey/runner.py` | Env injection for `passkey run` |
| `passkey/dirs.py` | Data dir; honors `PASSKEY_DATA_DIR` |
| `tests/conftest.py` | Hermetic suite |
| `.cursor/agents/` | sys-arch / engineer / release / review |
