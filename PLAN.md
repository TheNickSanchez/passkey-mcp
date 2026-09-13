# passkey-mcp — Plan to make it deployable

**Target:** first installable release **v0.4.0**.
**Current tree:** 0.3.1 (P0–P3 rewrite is in `main`, never published).

Deployable means a teammate can install a **pinned version** with pipx, MCP
configs can exec `passkey` from PATH, and a company security review can point
at CI + a PyPI artifact with provenance. It does **not** mean becoming a team
password manager.

Positioning for every doc and review ticket:

> Local-only helper that moves MCP/CLI secrets out of config files into the
> OS keychain. Not a shared vault. Not a 1Password replacement. Alpha, 0.x.

---

## Current state (verified 2026-09-12)

| Signal | Reality |
|--------|---------|
| Code on GitHub | Public, MIT, `TheNickSanchez/passkey-mcp` |
| PyPI `passkey-mcp` | **404** — README install commands do not work |
| GitHub Releases / tags | **None** |
| CI | Workflow exists; only run on `main` is **red** (326 passed, 1 failed) |
| Branch protection | **Off** — `main` has no required checks; force-push is allowed |
| Version | Duplicated: `pyproject.toml` and `passkey/__init__.py` both hardcode `0.3.1` |
| Version on PyPI | Never shipped. Do not tag 0.3.0 as the first release — its CHANGELOG still claims tests hang and `run` is auth-gated, which is no longer true |

P0–P3 from the 2026-07-28 roadmap **landed in code** (hermetic tests, opt-in
auth, `unwrap`, JSONC URL fix, CLI package, unified doctor, file-based index,
audit cap). They did **not** land as a release. Leftover from that work:

- CI failure: `tests/test_mcp_server.py::TestPasskeyDoctor::test_detects_missing_config`
  (`assert result["summary"]["failed"] > 0` → 0). Root cause: doctor only
  iterates `get_all_existing_paths()`, so on a clean runner the
  `FileNotFoundError` path never runs. The test is environment-dependent.
  **D0-1 decision: Option A** (hermetic tests; doctor stays silent on missing
  clients). See D0 below.
- `docs/SECURITY.md` claims **APPROVED FOR CORPORATE USE** (wrong deps,
  wrong version, SOC 2 theater). A reviewer will treat that as a credibility
  problem, not evidence.
- README still shows `pipx install passkey-mcp` and
  `passkey add … API_KEY=abc` (code prompts via `getpass`; values are not
  taken from argv). Development section still says `pip install -e ".[dev]"`
  — `[project.optional-dependencies] dev` was deleted; truth is `uv sync`.
- `doctor.py` recommends `pip install passkey-mcp` when the binary is missing.
- No `CONTRIBUTING.md`, no repo-root `SECURITY.md` policy, no Dependabot.

Historical P0–P3 tables are in git history (`0a9a46e` and parents). Do not
re-open them unless a regression shows up.

---

## D0 — Green `main` (v0.4.0-dev)

*Nothing gets published while CI is red.*

| # | Item | Acceptance |
|---|------|------------|
| 1 | **Decided — Option A** (see implementation below). Keep doctor iterating only existing paths. Make `TestPasskeyDoctor` hermetic. Do not treat a machine with no Claude/Cursor configs as a failed install. Do not require those configs on the runner. | `uv run pytest -q` green on a clean machine |
| 2 | **Mechanical (no design fork).** In `.github/workflows/ci.yml`, add `--locked` to both `uv sync` invocations: lint job `uv sync` → `uv sync --locked`; test job `uv sync --python ${{ matrix.python }}` → `uv sync --locked --python ${{ matrix.python }}`. | CI fails if `uv.lock` is stale |
| 3 | ~~Rewrite `AGENTS.md`.~~ **Done (this branch):** matches the tree (hermetic suite, opt-in auth, never on `run`, `uv` + `ruff.toml`, sys-* agents). | An agent (or teammate) following AGENTS.md does not hang on sudo |
| 4 | ~~One ruff config.~~ **Done (this branch):** `ruff.toml` is the only config; dropped `[tool.ruff]` from `pyproject.toml` and ignores for deleted `claude.py` / `claude_commands.py`. | `uv run ruff check passkey/ tests/` uses a single source of rules |
| 5 | Protect `main` — **maintainer-manual after this PR merges.** GitHub Settings clicks only. No workflow file, no Ruleset YAML in-repo, no `gh api` script. Click path below. | A red CI cannot merge. Direct push, force-push, and deletion of `main` are blocked. |

**Exit:** GitHub Actions green on `main` for macOS + Ubuntu, Python 3.10 and 3.14, and those checks are required to merge.

### D0-1 — Option A (decided)

**Why this, not B.** A clean machine with no Claude/Cursor configs is a normal
first-run, not a broken install. Doctor already iterates only
`adapter.get_all_existing_paths()` (`passkey/doctor.py` `run_diagnostics`,
Check 3). That is the honest product: diagnose configs that exist; stay silent
on clients the user never installed. Option B (emit skip/info for every
expected-but-absent adapter path) would add noise and a new summary status
without helping a first-run user. The CI red is a **test hermeticity** bug:
`test_detects_missing_config` patches `passkey.doctor.load_config` with
`FileNotFoundError` but never injects a path, so on a runner with an empty
`get_all_existing_paths()` the mock never fires and `failed` stays 0.
`test_all_checks_pass` has the same hole (green by accident when the loop is
empty). Do not “fix” CI by requiring real client configs on the runner, and
do not change doctor to fail (or skip/info) on missing clients.

**Do not edit `passkey/doctor.py`.** Behavior stays:

- Iterate `ADAPTERS` → `adapter.get_all_existing_paths()` only.
- Missing MCP clients: no check row (not `fail`, not `skip`, not `info`).
- `FileNotFoundError` or `MCPConfigError` from `load_config` on a path that
  *was* existing (TOCTOU / vanished file, or invalid JSON) stays `status: fail`
  and increments `summary.failed`. `test_handles_invalid_adapter_config`
  already covers `MCPConfigError`.

**Edit `tests/test_mcp_server.py` `TestPasskeyDoctor` only.** Reuse the
existing `_make_adapter(tmp_path)` helper (it `touch()`es a temp `config.json`
so `get_all_existing_paths()` returns that path) and
`patch('passkey.doctor.ADAPTERS', {"test": adapter})` — same pattern as
`test_reports_broken_server`, `test_reports_exposed_server`,
`test_handles_keychain_failure`, and `test_handles_invalid_adapter_config`.
Do not mock `get_all_existing_paths` on the real Claude/Cursor adapters; inject
a temp adapter instead.

Engineer checklist:

1. `test_detects_missing_config`: add `tmp_path`, build `_make_adapter(tmp_path)`,
   keep `load_config` → `FileNotFoundError`, wrap the `passkey_doctor()` call
   in `patch('passkey.doctor.ADAPTERS', {"test": adapter})`. Assertion stays
   `result["summary"]["failed"] > 0` (optionally also: a check whose `name`
   contains `config` and `status == "fail"`). This exercises the existing
   exception handler, not “user has no Claude.”
2. `test_all_checks_pass`: same adapter injection so the config loop actually
   runs. Keep `load_config` returning `{"mcpServers": {}}`, PATH and keychain
   mocks as today. Assert `result["summary"]["failed"] == 0`.
3. Add `test_missing_clients_are_not_failures`: PATH and keychain mocked to
   pass; `ADAPTERS` patched to `{}` **or** to one `_make_adapter`-style
   adapter whose `global_paths` point at a non-existent file (do **not**
   `touch()` it). Do not require `load_config` to fire. Assert
   `result["summary"]["failed"] == 0` and that no check with `config` in
   `name` has `status == "fail"`. This locks the first-run product rule.
4. Leave `test_detects_missing_passkey_in_path` as-is (its assertion does not
   depend on the config loop). Leave the four tests that already patch
   `ADAPTERS` as-is.
5. Do not add a third doctor. Do not require real `~/.claude.json` /
   Cursor configs. Acceptance: `uv run pytest -q` green on a clean machine
   (no MCP client configs on disk).

### D0-2 — `--locked` (mechanical)

File: `.github/workflows/ci.yml` only. Two lines, no other CI design:

- Job `lint`, step `run: uv sync` → `run: uv sync --locked`
- Job `test`, step `Sync dependencies` / `run: uv sync --python ${{ matrix.python }}`
  → `run: uv sync --locked --python ${{ matrix.python }}`

No new job, no cache change, no Python-version fork. If `uv.lock` is stale
relative to `pyproject.toml`, both jobs fail. That is the acceptance.

### D0-5 — Protect `main` (clicks only, after merge)

Do this on GitHub after the D0 PR is green and merged. Do **not** add a
workflow, a check-aggregator job, a `.github` ruleset file, or an API script.

1. Open `TheNickSanchez/passkey-mcp` on GitHub → **Settings** → **Branches**.
2. Under **Branch protection rules**, click **Add branch protection rule**.
   If the page only offers **Rulesets**, use **New ruleset** → **New branch
   ruleset**, target `main`, and apply the same constraints.
3. **Branch name pattern:** `main`.
4. Enable **Require a pull request before merging**. Leave **Require
   approvals** off (0 reviewers) while you are the only maintainer.
5. Enable **Require status checks to pass before merging**. After a green D0
   run, search and add the check names as they appear on the Actions tab
   (typical defaults from `.github/workflows/ci.yml`):
   - `lint`
   - `test (macos-latest, 3.10)`
   - `test (macos-latest, 3.14)`
   - `test (ubuntu-latest, 3.10)`
   - `test (ubuntu-latest, 3.14)`
   Require all five. Do not invent a sixth job to fold them into one name.
6. Enable **Do not allow bypassing the above settings** (include
   administrators) so a red run cannot merge from an admin laptop.
7. Leave **Allow force pushes** off. Leave **Allow deletions** off.
8. Click **Create** / **Save changes**.
9. **Settings** → **General** → scroll to **Pull Requests** → enable
   **Automatically delete head branches**.

Done when a direct push to `main` is rejected, a PR with a red required check
cannot merge, and `main` cannot be force-pushed or deleted.

---

## D1 — Honest docs (same milestone, no version bump)

Reviewers read README and `docs/SECURITY.md` before they read `bundle.py`.

| # | Item | Acceptance |
|---|------|------------|
| 1 | Replace `docs/SECURITY.md` with a GitHub-standard disclosure policy (how to report, what is in/out of scope, threat model in one page). **No “approved”, no SOC 2/OWASP scorecards.** Put a copy or link at repo root so GitHub’s Security tab picks it up. | File matches the code; InfoSec can attach it to a ticket |
| 2 | README: state the product is a local injector, not a password manager. Document `require-auth` as optional/off. Linux/Windows = best-effort vs macOS Keychain ACLs. | A security engineer cannot quote the README against the threat model |
| 3 | README install: **do not** advertise `pipx install passkey-mcp` until D2 lands. Until then, one labeled preview (`pipx install git+https://github.com/TheNickSanchez/passkey-mcp.git`) or “not published yet.” Drop `pip install` as a recommended path. | Following README cannot 404 |
| 4 | Delete the `API_KEY=abc` argv example. `passkey add --fields` prompts. | No documented secret-in-argv path |
| 5 | CHANGELOG: strike 0.3.0 “known issues” that were fixed in the rewrite; note share passphrases are 8 words / ~64 bits (not 4 / ~32). Add a Keep a Changelog `[Unreleased]` section (0.4.0 section is filled at D2). | Changelog matches code; new work has a place to land before the tag |
| 6 | Doctor copy: recommend `pipx install passkey-mcp` (after D2) not `pip install` | `passkey doctor` does not push people into system Python |
| 7 | README Development: `uv sync`, `uv run pytest`, `uv run ruff check`. Delete `pip install -e ".[dev]"`. | A new clone can run the suite from the README |
| 8 | Short `CONTRIBUTING.md`: same commands, PR = changelog note under `[Unreleased]`, do not commit to `main`. | Second contributor does not need to reverse-engineer AGENTS.md |

**Exit:** A cold reader of README + SECURITY.md would describe the same threat
model as `passkey/auth.py` and `passkey/mcp_server.py`.

---

## D2 — First installable artifact (v0.4.0)

This is the actual deploy.

| # | Item | Acceptance |
|---|------|------------|
| 1 | PyPI project `passkey-mcp`, published via **Trusted Publishing** (OIDC from GitHub Actions). No long-lived API token on a laptop. | `pip index versions passkey-mcp` shows 0.4.0 |
| 2 | Release workflow: tag `v0.4.0` → `uv build` → publish wheel + sdist → GitHub Release with those assets and CHANGELOG excerpt | `pipx install passkey-mcp==0.4.0` works on a clean Mac and Ubuntu |
| 3 | Confirm console scripts: `passkey` and `passkey-mcp-server` land on PATH via pipx | `which passkey`; Cursor can spawn `passkey run …` |
| 4 | pyproject hygiene: add 3.13/3.14 classifiers if we keep testing 3.14; keep `Development Status :: 3 - Alpha`; add Issues / Source / PyPI URLs alongside Homepage | `twine check dist/*` clean (or `uv build` equivalent) |
| 5 | Single-source version: `passkey --version` reads the package metadata (`importlib.metadata.version("passkey-mcp")`), not a second hardcoded string in `__init__.py` | Bumping `pyproject.toml` is the only edit for a release |
| 6 | README install block becomes the pipx command **pinned in the release notes** (`pipx install passkey-mcp==0.4.0`). Offer `uv tool install passkey-mcp` as the uv-native twin. | Glama / scrapers that copy the README stop advertising a 404 |
| 7 | Smoke the MCP path once after install: `passkey doctor`, wrap a dummy server, start it with no tty and no sudo | Wrapped server starts on stock macOS |

Release loop (this is the development-standard part of D2):

1. Move `[Unreleased]` bullets into `## 0.4.0 - YYYY-MM-DD`.
2. Bump the single version in `pyproject.toml`.
3. Tag annotated `v0.4.0` on the green commit.
4. GitHub Release body = that changelog section; attach wheel + sdist.
5. PyPI publish from the tag via Trusted Publishing.

Trusted Publishing setup (manual, once): PyPI account 2FA → pending publisher
for `TheNickSanchez/passkey-mcp` → workflow
`.github/workflows/release.yml` using `pypa/gh-action-pypi-publish` on
`release: published` (or `workflow_dispatch` + tag). Do not `twine upload`
from a developer machine.

**Exit:** The team install command is `pipx install passkey-mcp==0.4.0`.
Git clone is no longer the distribution channel.

---

## D3 — Reviewer / supply-chain extras (v0.4.x)

Needed for a company security ticket; not needed for three teammates who trust
you. Do it immediately after D2 if a review is inbound.

| # | Item | Acceptance |
|---|------|------------|
| 1 | CI job: `uv run pip-audit` or `osv-scanner` on the lockfile | Known CVEs in deps fail the build |
| 2 | Enable GitHub private vulnerability reporting on the repo | Matches SECURITY.md |
| 3 | Dependabot or `uv` dependabot-equivalent for `pyproject.toml` / Actions | `mcp` cannot silently float to 2.x (pin `>=1,<2` is load-bearing — FastMCP removed in v2) |
| 4 | Optional: setting to disable MCP write tools (`passkey_wrap_server`) for corporate installs | InfoSec can say “the assistant cannot rewrite configs” |
| 5 | Release attestations come for free with Trusted Publishing — link them from SECURITY.md | Reviewer can verify the wheel |

**Not in 0.4.x (do not block deploy on these):**

- Homebrew tap
- Windows CI (claim Windows as best-effort until a runner exists)
- npm / Docker / GUI
- Central vault, SSO, recovery, org admin
- 1.0 version label
- Contributor Covenant, DCO, signed-commit enforcement, CODEOWNERS
- Coverage gates, mypy/pyright, pre-commit hooks, issue/PR templates
- `pytest-cov` is already a dev dep — do not treat it as a gate until a job runs it

---

## Definition of done for “deployable”

A person who has never seen this repo can:

1. `pipx install passkey-mcp==0.4.0`
2. Run `passkey` → onboarding, create an entry, `passkey doctor` green enough to use
3. `passkey init --tool cursor` (or their tool) and start a wrapped MCP server with **no** sudo prompt
4. `passkey unwrap` to leave
5. Point InfoSec at: MIT license, threat model in SECURITY.md, green **required** CI on protected `main`, tagged `v0.4.0`, PyPI 0.4.0, GitHub Release

Until that list is true, do not call it deployed, and do not send the current
README to the team.

---

## Sequence

```
D0 (CI + protect main)  →  D1 (docs + CONTRIBUTING)  →  D2 (tag + PyPI)  →  D3 (audit/Dependabot)
         days                     same PR as D0 or next         after green main
```

D0 and D1 can ship as one PR to `main` with no tag. Protect `main` as soon as
that PR is merged (otherwise the next push can skip CI). D2 is the first tag.
Do not tag until GitHub Actions is green on the commit you tag.

---

## How we implement this plan

Cursor custom agents in `.cursor/agents/` (also the agent-profile picker):

| Agent | Role |
|-------|------|
| `sys-arch` | Research and `PLAN.md`. No production code. |
| `sys-engineer` | Implement and test with `uv`. |
| `sys-release` | Every PR: SemVer bump + `CHANGELOG.md` `[Unreleased]`. |
| `sys-review` | Read-only pre-PR review. |

Loop: arch (if needed) → engineer → release → review → PR. A hook denies
`git push` / `gh pr create` if `CHANGELOG.md` did not change vs `main`.
Until the 0.4.0 tag, PRs bump **0.3.x** (patch/minor). Do not use major
until 1.0.

---

## 1.0 (later, not this plan)

Keep 1.0 for product completeness (Windows CI, Homebrew optional, wrap-disable
default documented, no stale docs). Deployability is 0.4.0. Re-labeling to
1.0 without a published 0.4.x would repeat the 1.2.0 mistake.
