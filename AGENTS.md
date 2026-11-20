# passkey-mcp — Agent Notes

Verified 2026-11-20. Package version lives in `pyproject.toml`.
`passkey --version` reads `importlib.metadata.version("passkey-mcp")`.
This tree is **0.9.x**, Alpha (live on PyPI).

Positioning: local OS-keychain injector for MCP/CLI secrets. Not a team vault.

## Agents

This chat is the PM (`.cursor/rules/parent-pm.mdc`): sequence work, dispatch
the four specialists, discuss results with Nick. Do **not** add a fifth
profile. Custom agents in `.cursor/agents/`; invocation in
`.cursor/rules/agent-routing.mdc`. Parent Task prompts: branch, PLAN section
id, stop-before-commit. Do not paste a second PLAN.md.

| Profile | When |
|---------|------|
| `sys-arch` | `PLAN.md` names a design fork. `PLAN.md` only. Skip table refreshes. |
| `sys-engineer` | Implement and test. Handoff includes named untracked files. |
| `sys-release` | Every PR: SemVer, promote previous Unreleased → dated `## 0.3.N`, bump versions + `uv.lock`. |
| `sys-review` | Read-only merge lint. Uncommitted is expected if stop-before-commit. Nits do not restart the loop. |

Loop: arch **only if** a design fork exists → engineer → release → review →
PR (commit/PR only if Nick asks). Nits: engineer patches; do not re-run the
four-agent cycle unless Critical. A hook denies `git push` / `gh pr create`
if `CHANGELOG.md` is unchanged vs `main`. Until 1.0: **patch** = fix/docs/tests/CI; **minor** = feature or 0.x breaking;
**major** = 1.0.0 only. `PLAN.md` current-state describes **main**.

## Environment

- Python 3.10+; this machine is 3.14. **`uv` only — never pip.**
- `uv sync` creates `.venv/`. Lint config is **`ruff.toml` only**.
- Exercise the CLI with `uv run passkey …` from a clone. Team install is
  `uv tool install passkey-mcp` (or `pipx install passkey-mcp`).

```bash
uv sync
uv run pytest -q
uv run ruff check passkey/ tests/
uv run passkey --help
```

CI exists (`.github/workflows/ci.yml`: macOS + Ubuntu, 3.10 and 3.14). Do
not present a partial run as “all tests pass.” Do not ignore `test_cli.py`
/ `test_bundle.py` — those hangs are gone.

## Auth

Primary protection is the OS keychain ACL. Extra sudo/pkexec is **opt-in**
(`passkey config require-auth on`) and **never** applies to `passkey run`
(headless MCP). Windows extra-auth is a documented no-op.

Tests: `tests/conftest.py` sets `PASSKEY_DATA_DIR`, defangs scrypt to 2^14,
and mocks `passkey.cli._require_auth`. Never call real sudo/pkexec. Cover
`auth.py` only via `tests/test_auth.py` (subprocess mocked).

## Landmines

1. `mcp>=1.0.0,<2.0.0` is load-bearing (`FastMCP` removed in v2).
2. Secrets never in argv — `prompt_secret` / `getpass`. Never accept `pk1:` tokens or document `KEY=VALUE` on CLI `argv`.
3. Preserve the whole `Entry` on save (`config`, `created`, `source`, `policy`, `last_rotated`).
4. MCP tools: names/fields/status only — never values.
5. Config writes: atomic temp + `os.replace`. Exports: `O_EXCL`, `0o600`.
6. Crypto constants: import from `bundle.py`, never redefine.
7. Do not add a third doctor or a second permission checker (`doctor.py` and
   `bundle.check_file_permissions` are the singles).

## Release Gate (Minor `0.x.0` & Patch `0.x.y`)

Every minor (`0.x.0`) and patch/bugfix (`0.x.y`) release **must** complete all 6 steps in order before tagging:

1. **Version & Lockfile Sync:** Bump `[project] version = "X.Y.Z"` in `pyproject.toml` and run `uv lock` + `uv lock --check`.
2. **Changelog Promotion:** Promote `## [Unreleased]` in `CHANGELOG.md` to `## X.Y.Z (YYYY-MM-DD)` (categorized under `Added`, `Changed`, `Fixed`, `Security`) and open a fresh empty `## [Unreleased]` header above it.
3. **Full Docs, CLI & Wiki Parity:** Update `README.md`, `SECURITY.md` (whenever security or platform behavior changes), `passkey/completion.py`, `passkey/skills.py`, and all relevant guides in `docs/` (including `docs/08-CLI-Command-Reference.md` and `docs/09-MCP-Tools-and-Prompts-Reference.md`), verified automatically by `tests/test_docs_links.py`.
4. **Unpinned Install Strings:** Verify `passkey/doctor.py`, `README.md`, `SECURITY.md`, and `docs/01-Quickstart.md` use unpinned `uv tool install passkey-mcp` / `pipx install passkey-mcp`.
5. **Build & Local Install Smoke Check:** Run `uv build`, install the built wheel into the local user environment (`uv tool install --force dist/passkey_mcp-*.whl` or `pipx install --force dist/passkey_mcp-*.whl`), and verify `passkey --version` and `passkey doctor --json` succeed on the global `PATH` outside the repo `.venv`.
6. **Protected-`main` PR, Tag & Wiki Sync Output:** Because `Protect Main` blocks direct pushes and requires 6 CI checks, commit on `release/vX.Y.Z` (never directly on `main`) and output the exact commands to: (a) push `release/vX.Y.Z` and open/merge the PR after CI passes, (b) fast-forward `main`, create annotated tag `vX.Y.Z`, push `vX.Y.Z`, and publish the GitHub Release (triggering `.github/workflows/release.yml` Trusted Publishing), and (c) sync `docs/*.md` to `passkey-mcp.wiki.git`.

## Key files

| File | Purpose |
|------|---------|
| `PLAN.md` | Roadmap & deployability notes |
| `passkey/cli/` | CLI entry (`cli.py` is a shim) |
| `passkey/auth.py` | Opt-in OS prompt only |
| `passkey/keychain.py` | OS keychain + file index `entries.json` |
| `passkey/bundle.py` | AES-256-GCM + scrypt export/import |
| `passkey/sharing.py` | `pk1:` inline tokens + `PK01` `share`/`upload` |
| `passkey/mcp_config.py` | Tool adapters, JSONC, atomic save |
| `passkey/mcp_server.py` | FastMCP tools (no secret values) |
| `passkey/doctor.py` | Unified diagnostics |
| `passkey/runner.py` | Env injection for `passkey run` |
| `passkey/dirs.py` | Data dir; honors `PASSKEY_DATA_DIR` |
| `tests/conftest.py` | Hermetic suite |
| `.cursor/agents/` | sys-arch / engineer / release / review |
