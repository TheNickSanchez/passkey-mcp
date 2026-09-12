# passkey-mcp — Plan to make it deployable

**Target:** first installable release **v0.4.0**.
**Current tree:** 0.3.0 (P0–P3 rewrite is in `main`, never published).

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
| Version | Duplicated: `pyproject.toml` and `passkey/__init__.py` both hardcode `0.3.0` |
| Version on PyPI | Never shipped. Do not tag 0.3.0 as the first release — its CHANGELOG still claims tests hang and `run` is auth-gated, which is no longer true |

P0–P3 from the 2026-07-28 roadmap **landed in code** (hermetic tests, opt-in
auth, `unwrap`, JSONC URL fix, CLI package, unified doctor, file-based index,
audit cap). They did **not** land as a release. Leftover from that work:

- CI failure: `tests/test_mcp_server.py::TestPasskeyDoctor::test_detects_missing_config`
  (`assert result["summary"]["failed"] > 0` → 0). Root cause: doctor only
  iterates `get_all_existing_paths()`, so on a clean runner the
  `FileNotFoundError` path never runs. The test is environment-dependent.
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
| 1 | Fix the doctor test (mock an existing config path, or teach doctor to report missing configs as skip/info and assert that). Do not “fix” it by requiring real Claude/Cursor configs on the runner. | `uv run pytest -q` green on a clean machine |
| 2 | `uv sync --locked` in CI (today it is `uv sync`, so lockfile drift is silent) | CI fails if `uv.lock` is stale |
| 3 | ~~Rewrite `AGENTS.md`.~~ **Done (this branch):** matches the tree (hermetic suite, opt-in auth, never on `run`, `uv` + `ruff.toml`, sys-* agents). | An agent (or teammate) following AGENTS.md does not hang on sudo |
| 4 | ~~One ruff config.~~ **Done (this branch):** `ruff.toml` is the only config; dropped `[tool.ruff]` from `pyproject.toml` and ignores for deleted `claude.py` / `claude_commands.py`. | `uv run ruff check passkey/ tests/` uses a single source of rules |
| 5 | Protect `main` (GitHub settings, not a file): require a PR, require the CI check, no force-push, no deletions. “Require approvals” can stay off while you are the only maintainer. Turn on auto-delete head branches. | A red CI cannot merge. Settings → Branches → `main` is protected |

**Exit:** GitHub Actions green on `main` for macOS + Ubuntu, Python 3.10 and 3.14, and that check is required to merge.

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
