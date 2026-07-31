# passkey-mcp — Roadmap to 1.0

Supersedes `PHASE2.md` and `docs/SECURITY_AUDIT_2026.md` (deleted; recoverable from git history).

## Why we re-versioned to 0.x

A senior-level code review (2026-07-28) found the v1.2.0 label was not earned:

- The test suite **cannot run to completion** (hangs on real `sudo`, ~2 min of scrypt, pollutes the real audit log). The previous audit's claim "all existing tests pass" was only true on one machine with a warm sudo cache.
- The auth layer **breaks the core MCP flow** on stock macOS (see P1).
- No CI exists to catch any of this.

Version mapping: `1.0.0 → 0.0.1`, `1.1.0 → 0.1.0`, `1.2.0 → 0.2.0`.
Current release: **0.3.0** (this re-planning). The milestones below target 1.0.

---

## P0 — Test integrity (target: v0.4.0)

*Nothing else matters until the safety net actually works.*

| # | Item | Where | Acceptance criteria |
|---|------|-------|---------------------|
| 1 | Fix dev-deps split-brain: move `ruff`, `pytest-cov`, `pytest-timeout` into `[dependency-groups] dev`; delete duplicate `[project.optional-dependencies] dev` | `pyproject.toml` | `uv run ruff check` and `uv run pytest --timeout=60` work |
| 2 | Make tests hermetic: autouse fixture redirecting data dir (`PASSKEY_DATA_DIR` env override, add to `dirs.py`) and mocking `passkey.cli._require_auth` | `tests/conftest.py`, `passkey/dirs.py` | Full suite runs with zero writes to `~/Library/Application Support/passkey/` and zero `sudo` invocations |
| 3 | Defang scrypt in tests: monkeypatch `SCRYPT_N` to 2^14 via fixture; keep one production-parameter vector marked `@pytest.mark.slow` (deselected by default) | `tests/test_bundle.py`, `pyproject.toml` markers | `test_bundle.py` < 5s; suite < 30s total |
| 4 | Add CI: GitHub Actions running ruff + pytest on macOS and Ubuntu per push | `.github/workflows/ci.yml` | Green badge on a clean machine (proves 1–3) |
| 5 | Add `test_auth.py` with fully mocked subprocess | `tests/test_auth.py` | `auth.py` covered without touching real sudo/pkexec |

## P1 — Auth redesign (target: v0.5.0)

*The current design fails the exact scenario the tool exists for.*

**Problem.** `_require_auth` gates `passkey run` (`cli.py:506`) — the command every passkey-wrapped MCP server executes headless. On stock macOS (no `pam_tid` in `/etc/pam.d/sudo` — that's opt-in), `sudo -v` fails without a tty → every wrapped MCP server fails to start. It only works on the dev machine because of a custom PAM config, and even there it rides the 5-minute sudo timestamp cache. The Windows implementation (`ShellExecuteW runas` → separate elevated `cmd /c echo`) proves nothing about the current process. Threat model is also inconsistent: `list`/`info`/`status` and all MCP read tools skip auth entirely.

| # | Item | Acceptance criteria |
|---|------|---------------------|
| 1 | Remove `_require_auth` from `run` and every other code path MCP servers invoke headless | Wrapped MCP server starts on stock macOS with no tty |
| 2 | Replace sudo-as-oracle with: (a) rely on the OS keychain's own ACL prompts (macOS already gates per-binary), plus (b) opt-in `require_auth = true` config flag, documented as terminal-only | Auth is off by default for headless paths; docs explain the tradeoff |
| 3 | Ship `passkey unwrap` (restore a server config from passkey-wrapped form back to inline command) or prominently document `.backup` restore in `init` output | Users can leave the one-way door |
| 4 | Decide the fate of `auth.py` Windows path (theater) — fix or drop with a note | No pretend-security |

## P2 — Correctness (target: v0.6.0)

| # | Bug | Where | Fix |
|---|-----|-------|-----|
| 1 | JSONC comment-stripper destroys URLs (`https://…` → parse error) — breaks any OpenCode/Zed config with a remote MCP server | `mcp_config.py:379` | Strip comments only outside string literals (small state machine) or use `jsonc-parser`; add regression test with URLs |
| 2 | Audit log mislabels creates as updates | `keychain.py:200` | `"create" if is_new else "update"` (drop the `is_update` condition); regression test |
| 3 | `cmd_set_field` rebuilds `Entry` and silently drops `config`, `created`, `source` | `commands.py:413` | Mutate the existing entry and save; test config preservation |
| 4 | Importer `overwrite` mode drops `config` | `importers.py:70-76` | Preserve `config` like `created` |
| 5 | Invalid entry names in bundles/imports raise uncaught `ValueError` → partial import + traceback | `bundle.py:236`, `importers._handle_existing` | Validate name, skip-with-warning, continue import |
| 6 | `receive` double-logs `bundle_import` | `sharing.py:269` | Remove the outer `log_operation` (inner one in `import_bundle` suffices) |
| 7 | Dead code: discarded expressions | `sharing.py:266`, `health.py:88,186`, `mcp_commands.py:350` | Delete (ruff B018 catches once ruff runs) |
| 8 | `audit --summary` claims "last 30 days" but never filters by date | `health.py:174` | Filter by timestamp or fix the label |

## P3 — Structure & polish (target: v0.7.x → 1.0)

| # | Item | Notes |
|---|------|-------|
| 1 | Split `cli.py` (829 lines, 26-branch dispatch, argparse-private help formatter) into a `cli/` package | Move all `sys.exit` to the outermost layer; library code (`runner`, `interactive`) must raise, not exit |
| 2 | Collapse three doctor implementations into one (`mcp_commands.cmd_doctor`, `health.cmd_doctor_deep`, `mcp_server.passkey_doctor`) | Depth as a flag, not a fork |
| 3 | Delete or date-bound the legacy shims: `claude.py`, `claude_commands.py`, `Legacy` command group, MCP tool aliases | One downstream user; don't carry 1.x baggage into a real 1.0 |
| 4 | Merge the two file-permission checkers (`bundle.check_file_permissions` vs `importers._check_file_permissions`) | Same behavior, one implementation |
| 5 | Reconsider metadata-in-keychain (`__entries__` index + lock file + dangling cleanup) | File-based index with atomic writes removes ~⅓ of `keychain.py` |
| 6 | Audit log: rotation or size cap; stop per-entry `read` spam from `passkey list` | Log is currently unbounded |
| 7 | Fix `authors = nick@example.com` placeholder in `pyproject.toml` | Release metadata hygiene |
| 8 | `passkey_status` MCP tool calls `list_entries()` inside the per-config loop | Hoist out of loop |

## Definition of done for 1.0

- Full suite green in CI on a clean macOS + Ubuntu runner, < 60s.
- Zero writes outside the configured data dir during tests.
- Wrapped MCP servers start on stock macOS (no custom PAM) with no tty.
- JSONC configs with URLs parse correctly.
- No dead code, no duplicate doctor, no legacy shims.
