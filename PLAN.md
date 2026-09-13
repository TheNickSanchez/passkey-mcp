# passkey-mcp — Plan to make it deployable

**Target:** first installable release **v0.4.0**.
**Current tree:** 0.3.3 on branch `d1-honest-docs` (not tagged; `main` is still 0.3.2 until this PR merges).

Deployable means a teammate can install a **pinned version** with pipx, MCP
configs can exec `passkey` from PATH, and a company security review can point
at CI + a PyPI artifact with provenance. It does **not** mean becoming a team
password manager.

Positioning for every doc and review ticket:

> Local-only helper that moves MCP/CLI secrets out of config files into the
> OS keychain. Not a shared vault. Not a 1Password replacement. Alpha, 0.x.

---

## Current state (verified 2026-09-13)

| Signal | Reality |
|--------|---------|
| Code on GitHub | Public, MIT, `TheNickSanchez/passkey-mcp` |
| PyPI `passkey-mcp` | **404** — unpublished. Do not advertise a PyPI install until D2. |
| GitHub Releases / tags | **None**. First tag is 0.4.0 (D2). Do not tag 0.3.x. |
| CI | **Green on `main`** after D0-1/D0-4: macOS + Ubuntu, Python 3.10 and 3.14 (`lint` + four `test` jobs). `--locked` sync. Do not re-verify with a partial local run. |
| Branch protection | **Off** — D0-5 not done. `main` has no required checks; force-push and direct push are still allowed. Nick clicks later (no workflow, no ruleset YAML, no `gh api`). |
| Version | Duplicated: `pyproject.toml` and `passkey/__init__.py` both hardcode `0.3.3` on this branch (not tagged) |
| Version on PyPI | Never shipped. Do not tag 0.3.x. First tag is 0.4.0 (D2). |

P0–P3 from the 2026-07-28 roadmap **landed in code** (hermetic tests, opt-in
auth, `unwrap`, JSONC URL fix, CLI package, unified doctor, file-based index,
audit cap). D0-1 through D0-4 **landed in 0.3.2**. D1-1 through D1-8
**landed on this branch as 0.3.3** (docs honesty). Nothing is tagged.
Remaining leftovers — **not D1**:

- PyPI `passkey-mcp` is **404**. No GitHub Releases / tags. Unpublished.
- Branch protection is **off** (D0-5 — Nick’s Settings clicks; no workflow,
  no ruleset YAML, no `gh api`).
- Dependabot / private vuln reporting / PyPI provenance wait for D2/D3.

~~Struck (done in D1 / 0.3.3):~~ root `SECURITY.md` + `docs/SECURITY.md`
stub (no “approved” / SOC 2 theater); README git preview + `uv run passkey`
(no PyPI pipx, no `pip install`, no `API_KEY=abc` argv); doctor git-preview
copy; `CONTRIBUTING.md`; `AGENTS.md` leftover red-test sentence; CHANGELOG
0.2.0 share entropy **8 words / ~64 bits**; 0.3.2 notes promoted out of
`[Unreleased]`.

Historical P0–P3 tables are in git history (`0a9a46e` and parents). Do not
re-open them unless a regression shows up.

---

## D0 — Green `main` (v0.4.0-dev)

*D0-1 through D0-4 are done on `main` (0.3.2). CI is green. Remaining is D0-5 (Nick’s Settings clicks). Do not publish until D2.*

| # | Item | Acceptance |
|---|------|------------|
| 1 | ~~CI hermeticity (Option A).~~ **Done (0.3.2):** doctor still iterates only existing paths; `TestPasskeyDoctor` injects a temp adapter. Missing MCP clients are not a failed install. | Green on a clean runner (no Claude/Cursor configs) |
| 2 | ~~`uv sync --locked`.~~ **Done (0.3.2):** both CI jobs (`lint`, `test`) use `--locked`. | CI fails if `uv.lock` is stale |
| 3 | ~~Rewrite `AGENTS.md`.~~ **Done (0.3.1 / 0.3.2):** matches the tree (hermetic suite, opt-in auth, never on `run`, `uv` + `ruff.toml`, sys-* agents). D1 struck the leftover “only known red test” sentence. | An agent following AGENTS.md does not hang on sudo |
| 4 | ~~One ruff config.~~ **Done (0.3.1):** `ruff.toml` is the only config; dropped `[tool.ruff]` from `pyproject.toml` and ignores for deleted `claude.py` / `claude_commands.py`. | `uv run ruff check passkey/ tests/` uses a single source of rules |
| 5 | Protect `main` — **maintainer-manual clicks for Nick after this PR merges (or anytime; not a workflow).** GitHub Settings only. No workflow file, no Ruleset YAML in-repo, no `gh api` script. Click path below. | A red CI cannot merge. Direct push, force-push, and deletion of `main` are blocked. |

**Exit:** GitHub Actions green on `main` for macOS + Ubuntu, Python 3.10 and 3.14 (**met**), and those checks are required to merge (**not met** until D0-5).

### D0-1 — Option A (done in 0.3.2)

*Historical decision record. Do not re-open unless the doctor tests regress.*

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

### D0-2 — `--locked` (done in 0.3.2)

*Landed. Do not re-edit CI for this.*

File: `.github/workflows/ci.yml` only. Two lines, no other CI design:

- Job `lint`, step `run: uv sync` → `run: uv sync --locked`
- Job `test`, step `Sync dependencies` / `run: uv sync --python ${{ matrix.python }}`
  → `run: uv sync --locked --python ${{ matrix.python }}`

No new job, no cache change, no Python-version fork. If `uv.lock` is stale
relative to `pyproject.toml`, both jobs fail. That is the acceptance.

### D0-5 — Protect `main` (clicks only; D0 PR already merged)

Do this on GitHub when Nick is ready (after D1 is fine). Do **not** add a
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

## D1 — Honest docs (**done on this branch**, patch 0.3.3)

*D1-1 through D1-8 landed on `d1-honest-docs` as 0.3.3. Do not re-implement.
Do not start D2. Outlines below are the decision record.*

Reviewers read README and SECURITY.md before they read `bundle.py`. This PR
was **docs honesty**, classified **patch**. sys-release already bumped
**0.3.2 → 0.3.3** and promoted 0.3.2 notes into `## 0.3.2 (2026-09-13)`.
Do **not** bump to 0.4.0. D2/D3 stay out of scope.

| # | Item | Acceptance |
|---|------|------------|
| 1 | ~~Root `SECURITY.md` + `docs/` stub.~~ **Done (0.3.3):** GitHub-standard disclosure + threat model matching `auth.py` / `mcp_server.py`. No “approved”, no SOC 2 / OWASP. | File matches the code; InfoSec can attach it |
| 2 | ~~README product + `require-auth`.~~ **Done (0.3.3):** local injector, not a password manager; extra auth optional/off; Linux/Windows best-effort vs macOS Keychain ACLs. | README cannot be quoted against the threat model |
| 3 | ~~README install.~~ **Done (0.3.3):** labeled git preview + `uv run passkey`. No PyPI pipx, no `pip install`. | Following README cannot 404 |
| 4 | ~~Argv example.~~ **Done (0.3.3):** `API_KEY=abc` removed; `passkey add --fields` prompts via `getpass`. | No documented secret-in-argv path |
| 5 | ~~CHANGELOG honesty.~~ **Done (0.3.3):** 0.3.0 known-issues stay gone; 0.2.0 share line is **8 words / ~64 bits**; 0.3.2 notes promoted; D1 notes under `[Unreleased]`. | Changelog matches code |
| 6 | ~~Doctor copy.~~ **Done (0.3.3):** git preview + `uv run passkey`. No `pip install`, no PyPI pipx. After D2, switch to pinned pipx — **not now**. | `passkey doctor` does not 404 |
| 7 | ~~README Development + `AGENTS.md`.~~ **Done (0.3.3):** `uv sync` / `uv run pytest` / `uv run ruff check`; leftover red-test sentence struck. | A new clone can run the suite from the README |
| 8 | ~~`CONTRIBUTING.md`.~~ **Done (0.3.3):** same commands; PR = `[Unreleased]` note; do not commit to `main`. | Second contributor does not reverse-engineer AGENTS.md |

**Exit:** A cold reader of README + root `SECURITY.md` would describe the same
threat model as `passkey/auth.py` and `passkey/mcp_server.py`. **Met on this
branch.**

### D1-1 — locked: `SECURITY.md` outline (done in 0.3.3; keep as record)

**Files:** create `/SECURITY.md`. Replace `/docs/SECURITY.md` with a 3–5 line
stub: title + “the policy lives at the [repository root](../SECURITY.md).”
Delete the fake assessment (APPROVED, SOC 2, OWASP, “no known CVEs”,
placeholder `[Your Team]` / `[Security Team]`).

**Contact check (do not invent an email):** `pyproject.toml` author is
`Nick Sanchez` with **no email**. README has none. Old `docs/SECURITY.md`
placeholders are not a contact. Do not add a SOC2 / vendor inbox.

Copy this structure. One page. Match the code.

```
# Security Policy

## Product
Local OS-keychain injector for MCP/CLI secrets. Moves secrets out of
config files into the OS keychain (`keyring`, service name `passkey`).
Not a team vault. Not a password-manager vendor. Not multi-tenant.
Alpha, 0.x. MIT license. Point InfoSec at the MIT license + this file
(+ green CI; required checks after D0-5). Do not claim corporate
approval.

## Reporting
1. Prefer GitHub private vulnerability reporting if it is enabled on
   TheNickSanchez/passkey-mcp.
2. Else open a public issue that contains **no secrets** (no tokens,
   no bundle files, no env dumps, no keychain exports).
3. There is no security email in this repo. Do not invent one.

## In scope
- Secret leakage via CLI, MCP tools, doctor, audit, export / import / share
- Local MCP config rewrite by `passkey_wrap_server` (local file write,
  not remote RCE)
- Keychain + index handling (`entries.json` is names only; values live
  in the OS keychain)
- `passkey run` environment injection (child-process env exposure)
- Docs / install commands that advertise an unpublished PyPI package

## Out of scope
- Multi-tenant vault, SSO, recovery, org admin, cloud sync
- Physical access to an unlocked machine, root/admin compromise,
  keyloggers, memory forensics
- Remote RCE / network attack surface (this product has no server and
  makes no network calls)
- Corporate approval, SOC 2, OWASP scorecards
- Windows extra-auth (documented no-op; see threat model)

## Threat model (must match passkey/auth.py, mcp_server.py, keychain.py, runner.py)

- Secrets never in argv. Interactive input uses `getpass`. Do not
  document `KEY=VALUE` on the command line.
- MCP tools (`passkey_list`, `passkey_fields`, `passkey_status`,
  `passkey_doctor`, `passkey_wrap_server`) return names, field names,
  and status only — **never secret values**.
- `passkey run` injects env vars into a child process and is **never**
  extra-auth-gated (headless MCP). See `cli/__init__.py` (`run` branch)
  and `runner.py`. Extra sudo/pkexec is opt-in
  (`passkey config require-auth on`) and applies only to interactive
  CLI commands. It never applies to `run`.
- Windows extra-auth is a documented no-op (`auth.py`
  `_authenticate_windows` returns True). Protection is Credential
  Manager ACLs alone. Linux extra-auth is `pkexec` with a getpass+sudo
  fallback. macOS extra-auth is `sudo -v` (Touch ID if pam_tid).
- Primary protection is the OS keychain ACL via `keyring`. macOS
  Keychain ACLs (app prompt / login keychain) are the strong case.
  Linux Secret Service and Windows Credential Manager are
  **best-effort** by comparison; Linux also needs a running, unlocked
  keyring daemon.
- Entry index `entries.json` (data dir) is names only, written atomically
  at `0o600`. Secret payloads are keychain items, not that file.
- `passkey_wrap_server` rewrites local MCP configs
  (`.json` / `.jsonc`, user paths; skips a short list of system
  prefixes). In scope as a **local config rewrite**, not remote RCE.
  Optional later control: D3-4 (disable write tools) — not this PR.
- `passkey run` prints a stderr warning: env vars can be visible to
  other processes on the same machine. That is an accepted, documented
  risk, not a hidden one.
- No network, no telemetry. Supply chain **is** the install path.
  PyPI is unpublished; distribution today is a git preview until D2.

## What this file must not say
- “Approved”, “approved for corporate use”, SOC 2, OWASP Top 10
  scorecards, “no known vulnerabilities”, invented dependency counts,
  or a fake reviewer sign-off.
```

### D1-6 — locked: doctor (and README) install strings (done in 0.3.3)

*Landed. Do not change these strings until D2.*

**File:** `passkey/doctor.py` — the `passkey_in_path` fail recommendation.
README install block uses the same two commands.

**Until D2, use exactly:**

- Git preview: `pipx install git+https://github.com/TheNickSanchez/passkey-mcp.git`
- This clone: `uv run passkey`

**Do not use:**

- `pip install passkey-mcp`
- `pipx install passkey-mcp` (PyPI 404)
- `pip install -e .` / `pip install -e ".[dev]"` as the recommended path

Suggested doctor sentence (engineer may wrap for line length, not change
the commands):

`Install passkey: pipx install git+https://github.com/TheNickSanchez/passkey-mcp.git (git preview until PyPI) or uv run passkey from a clone.`

After D2, README + doctor may switch to `pipx install passkey-mcp==0.4.0`.
Not this PR.

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
D0-1..D0-4 (done, 0.3.2, CI green)  →  D1 (done on this branch, 0.3.3)  →  D0-5 (Nick clicks)  →  D2 (tag + PyPI)  →  D3
```

D0 code shipped on `main` as 0.3.2. **D1 landed on `d1-honest-docs` as 0.3.3**
(not tagged). Next is **D0-5** (Nick’s Settings clicks, not a workflow),
then D2. Do **not** start D2. D2 is the first tag and the first PyPI
publish. Do not tag until GitHub Actions is green on the commit you tag.

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
