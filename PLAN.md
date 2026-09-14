# passkey-mcp — Plan to make it deployable

**Target:** first installable release **v0.4.0**.
**Current tree:** 0.4.1 (D2-6 install pin). PyPI and tag remain **0.4.0**.

Deployable means a teammate can install a **pinned version** with pipx, MCP
configs can exec `passkey` from PATH, and a company security review can point
at CI + a PyPI artifact with provenance. It does **not** mean becoming a team
password manager.

Positioning for every doc and review ticket:

> Local-only helper that moves MCP/CLI secrets out of config files into the
> OS keychain. Not a shared vault. Not a 1Password replacement. Alpha, 0.x.

---

## Current state (verified 2026-09-14)

| Signal | Reality |
|--------|---------|
| Code on GitHub | Public, MIT, `TheNickSanchez/passkey-mcp` |
| PyPI `passkey-mcp` | **0.4.0** — Trusted Publishing from GitHub Release `v0.4.0`. Team install: `pipx install passkey-mcp==0.4.0`. |
| GitHub Releases / tags | **`v0.4.0`**. Do not retag 0.4.0. Later docs patches bump 0.4.x without a new tag unless Nick publishes. |
| CI | **Green on `main`**. macOS + Ubuntu, Python 3.10 and 3.14 (`lint` + four `test` jobs) plus `audit`. `--locked` sync. Dependabot + `release.yml` on `main`. Dependabot ignores `mcp` semver-major. Do not re-verify with a partial local run. |
| Branch protection | **On** — ruleset **Protect Main**: required checks are `lint` + four `test` jobs + `audit`. Direct push, force-push, and deletion of `main` are blocked. |
| Version | `0.4.1`. Single-source: `passkey --version` reads `importlib.metadata.version("passkey-mcp")`. Stay Alpha. Local keychain injector, not a vault. PyPI artifact stays 0.4.0 until a later Release. |
| Version on PyPI | **0.4.0**. README/doctor pin is D2-6 (this PR). Do not advertise unpinned `pip install passkey-mcp` as the team command. |
| Private vuln reporting | **On**. Matches `SECURITY.md`. |

P0–P3 from the 2026-07-28 roadmap **landed in code** (hermetic tests, opt-in
auth, `unwrap`, JSONC URL fix, CLI package, unified doctor, file-based index,
audit cap). D0-1 through D0-4 **landed in 0.3.2**. D1-1 through D1-8
**landed on `main` as 0.3.3** (docs honesty). D2 prep **landed in 0.3.5**
(PR #5: Trusted Publishing workflow, Dependabot, lockfile audit,
single-source `--version`). Tree on `main` is **0.4.0 tagged**; PyPI **0.4.0**
is live. Protect Main requires `lint` + four `test` jobs + `audit`.
Dependabot ignores `mcp` semver-major (PR #7 widened `mcp>=1,<2`
to `<3`; the range stays `mcp>=1.0.0,<2.0.0`). CI is green. Private vuln
reporting is on. Stay Alpha. Local keychain injector, not a vault.
Remaining leftovers:

- D2-7 (MCP smoke) and D3-4 / D3-5 (wrap-disable, attestations) are still
  open. Link PyPI attestations in SECURITY.md after D3-5.

~~Struck (done in D1 / 0.3.3):~~ root `SECURITY.md` + `docs/SECURITY.md`
stub (no “approved” / SOC 2 theater); README git preview + `uv run passkey`
(no PyPI pipx, no `pip install`, no `API_KEY=abc` argv); doctor git-preview
copy; `CONTRIBUTING.md`; `AGENTS.md` leftover red-test sentence; CHANGELOG
0.2.0 share entropy **8 words / ~64 bits**; 0.3.2 notes promoted out of
`[Unreleased]`.

~~Struck (done in 0.3.5 / PR #5):~~ D0-5 Protect Main (`lint` + four `test`
jobs); D2-4 pyproject classifiers + URLs (Alpha, unpublished); D2-5
single-source `--version`; D3-1 CI `pip-audit`; D3-2 private vuln reporting;
D3-3 Dependabot for uv + Actions (`mcp` stays `<2`).

~~Struck (done in 0.4.0):~~ Protect Main required check `audit` (Nick added
it). Dependabot ignore `mcp` semver-major. Tag `v0.4.0`. PyPI 0.4.0 via
Trusted Publishing.

~~Struck (done in 0.4.1 / D2-6):~~ README + doctor install strings are
pinned pipx `passkey-mcp==0.4.0` (uv tool twin). Clone stays `uv run passkey`.
Do not mark D2-7 / D3-4 / D3-5 done.

Historical P0–P3 tables are in git history (`0a9a46e` and parents). Do not
re-open them unless a regression shows up.

---

## D0 — Green `main` (v0.4.0-dev)

*D0-1 through D0-5 are done on `main` (0.3.2 / Protect Main). CI is green and required to merge (`lint` + four `test` jobs + `audit`). Do not publish until D2.*

| # | Item | Acceptance |
|---|------|------------|
| 1 | ~~CI hermeticity (Option A).~~ **Done (0.3.2):** doctor still iterates only existing paths; `TestPasskeyDoctor` injects a temp adapter. Missing MCP clients are not a failed install. | Green on a clean runner (no Claude/Cursor configs) |
| 2 | ~~`uv sync --locked`.~~ **Done (0.3.2):** both CI jobs (`lint`, `test`) use `--locked`. | CI fails if `uv.lock` is stale |
| 3 | ~~Rewrite `AGENTS.md`.~~ **Done (0.3.1 / 0.3.2):** matches the tree (hermetic suite, opt-in auth, never on `run`, `uv` + `ruff.toml`, sys-* agents). D1 struck the leftover “only known red test” sentence. | An agent following AGENTS.md does not hang on sudo |
| 4 | ~~One ruff config.~~ **Done (0.3.1):** `ruff.toml` is the only config; dropped `[tool.ruff]` from `pyproject.toml` and ignores for deleted `claude.py` / `claude_commands.py`. | `uv run ruff check passkey/ tests/` uses a single source of rules |
| 5 | ~~Protect `main`.~~ **Done (ruleset Protect Main):** required checks `lint` + four `test` jobs + `audit`. Direct push, force-push, and deletion of `main` are blocked. No workflow, no ruleset YAML, no `gh api`. | A red CI cannot merge. Direct push, force-push, and deletion of `main` are blocked. |

**Exit:** GitHub Actions green on `main` for macOS + Ubuntu, Python 3.10 and 3.14 (**met**), and those checks are required to merge (**met** — Protect Main: `lint` + four `test` jobs + `audit`).

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

### D0-5 — Protect `main` (done)

*Landed. Ruleset Protect Main requires `lint` + four `test` jobs + `audit`.
Do **not** add a workflow, a check-aggregator job, a `.github` ruleset file,
or an API script.*

~~Struck leftover:~~ Nick added required check `audit` in Settings. Required
list is `lint`, the four `test (os, py)` jobs, and `audit`. Do not call
`gh api`. Do not add ruleset YAML.

**Met.** A direct push to `main` is rejected, a PR with a red required check
cannot merge, and `main` cannot be force-pushed or deleted.

---

## D1 — Honest docs (**done on `main`**, patch 0.3.3)

*D1-1 through D1-8 landed on `main` as 0.3.3. Do not re-implement.
Outlines below are the decision record.*

Reviewers read README and SECURITY.md before they read `bundle.py`. That PR
was **docs honesty**, classified **patch**. sys-release bumped
**0.3.2 → 0.3.3** and promoted 0.3.2 notes into `## 0.3.2 (2026-09-13)`.
Do **not** bump to 0.4.0 here. D2 is the first tag and first PyPI publish
— prep can land; do not mark D2 done until 0.4.0 is on PyPI.

| # | Item | Acceptance |
|---|------|------------|
| 1 | ~~Root `SECURITY.md` + `docs/` stub.~~ **Done (0.3.3):** GitHub-standard disclosure + threat model matching `auth.py` / `mcp_server.py`. No “approved”, no SOC 2 / OWASP. | File matches the code; InfoSec can attach it |
| 2 | ~~README product + `require-auth`.~~ **Done (0.3.3):** local injector, not a password manager; extra auth optional/off; Linux/Windows best-effort vs macOS Keychain ACLs. | README cannot be quoted against the threat model |
| 3 | ~~README install.~~ **Done (0.3.3 / superseded 0.4.1):** was git preview. D2-6 switched to pinned pipx. | Following README cannot 404 |
| 4 | ~~Argv example.~~ **Done (0.3.3):** `API_KEY=abc` removed; `passkey add --fields` prompts via `getpass`. | No documented secret-in-argv path |
| 5 | ~~CHANGELOG honesty.~~ **Done (0.3.3):** 0.3.0 known-issues stay gone; 0.2.0 share line is **8 words / ~64 bits**; 0.3.2 notes promoted; D1 notes under `[Unreleased]`. | Changelog matches code |
| 6 | ~~Doctor copy.~~ **Done (0.3.3 / superseded 0.4.1):** was git preview. D2-6 switched to pinned pipx. | `passkey doctor` does not 404 |
| 7 | ~~README Development + `AGENTS.md`.~~ **Done (0.3.3):** `uv sync` / `uv run pytest` / `uv run ruff check`; leftover red-test sentence struck. | A new clone can run the suite from the README |
| 8 | ~~`CONTRIBUTING.md`.~~ **Done (0.3.3):** same commands; PR = `[Unreleased]` note; do not commit to `main`. | Second contributor does not reverse-engineer AGENTS.md |

**Exit:** A cold reader of README + root `SECURITY.md` would describe the same
threat model as `passkey/auth.py` and `passkey/mcp_server.py`. **Met on `main`.**

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

### D1-6 — locked: doctor (and README) install strings (done in 0.3.3; superseded D2-6 / 0.4.1)

*Historical lock. D2-6 replaced these strings.*

**Now (0.4.1):**

- Team: `pipx install passkey-mcp==0.4.0`
- uv twin: `uv tool install passkey-mcp`
- This clone: `uv run passkey`

**Do not use** unpinned `pip install passkey-mcp` as the documented team path.

Doctor sentence:

`Install passkey: pipx install passkey-mcp==0.4.0 or uv tool install passkey-mcp.`

---

## D2 — First installable artifact (v0.4.0)

This is the actual deploy.

| # | Item | Acceptance |
|---|------|------------|
| 1 | ~~PyPI project `passkey-mcp`.~~ **Done (0.4.0):** Trusted Publishing from GitHub Release. | `pip index versions passkey-mcp` shows 0.4.0 |
| 2 | ~~Release workflow.~~ **Done (0.4.0):** `v0.4.0` Release ran `release.yml`. | `pipx install passkey-mcp==0.4.0` works |
| 3 | ~~Console scripts.~~ **Done (0.4.0):** `passkey` and `passkey-mcp-server` on PATH via pipx. | `which passkey` |
| 4 | ~~pyproject hygiene.~~ **Done (0.3.5):** 3.13/3.14 classifiers; `Development Status :: 3 - Alpha`; Issues / Source / PyPI URLs alongside Homepage. Stay Alpha. | `twine check dist/*` clean (or `uv build` equivalent) |
| 5 | ~~Single-source version.~~ **Done (0.3.5):** `passkey --version` reads `importlib.metadata.version("passkey-mcp")`. | Bumping `pyproject.toml` is the only edit for a release |
| 6 | ~~README / doctor pin.~~ **Done (0.4.1):** `pipx install passkey-mcp==0.4.0`; `uv tool install passkey-mcp` twin. Clone stays `uv run passkey`. | Glama / scrapers that copy the README stop advertising a 404 |
| 7 | Smoke the MCP path once after install: `passkey doctor`, wrap a dummy server, start it with no tty and no sudo | Wrapped server starts on stock macOS |

Release loop (this is the development-standard part of D2):

1. Move `[Unreleased]` bullets into `## 0.4.0 - YYYY-MM-DD`.
2. Bump the single version in `pyproject.toml`.
3. Tag annotated `v0.4.0` on the green commit.
4. Publish a GitHub Release on that tag (body = that changelog section).
5. `release: published` runs `release.yml`: `uv build`, Trusted Publish, attach wheel + sdist.

Trusted Publishing setup (manual, once; trigger locked in D2-1 / D2-2
below): PyPI account 2FA → pending publisher for
`TheNickSanchez/passkey-mcp` → workflow `.github/workflows/release.yml`
using `pypa/gh-action-pypi-publish` on `release: published` **only**. Do
not `twine upload` from a developer machine.

**Exit:** The team install command is `pipx install passkey-mcp==0.4.0`.
Git clone is no longer the distribution channel.

### D2-1 / D2-2 — locked: Trusted Publishing trigger

**Locked: `on: release: types: [published]`.** Not `workflow_dispatch` +
tag. File stays `.github/workflows/release.yml` using
`pypa/gh-action-pypi-publish`. Do not add both. Do not invent `push:
tags` or a third trigger.

**Why this, not dispatch.** Publishing a GitHub Release is the
intentional 0.4.0 gate (drafts do not fire). A tag alone does not
publish. `workflow_dispatch` can run on a branch ref and is the
unintended-trigger example in PyPI’s Trusted Publishing security model.
Solo maintainer: the Release click is enough; a second Actions dispatch
can leave “tagged but PyPI 404” or “on PyPI but no Release.”

- Pending publisher (Nick, once): owner `TheNickSanchez`, repo
  `passkey-mcp`, workflow filename `release.yml`. No laptop API token.
- Workflow: `release: published` only → `uv build` → Trusted Publish
  wheel + sdist → attach those assets to the same Release.
- Split build and publish jobs; `id-token: write` only on publish.
- First tag is `v0.4.0`. Do not tag 0.3.x. PyPI `passkey-mcp` stays 404
  until that publish. Stay Alpha. Local keychain injector, not a vault.

**Non-goals (this lock):** do not mark D2 done, tag, or upload from this
PR; no ruleset YAML; no required GitHub environment (Release publish is
the human gate; environment is optional later).

---

## D3 — Reviewer / supply-chain extras (v0.4.x)

Needed for a company security ticket; not needed for three teammates who trust
you. Do it immediately after D2 if a review is inbound.

| # | Item | Acceptance |
|---|------|------------|
| 1 | ~~CI job: `uv run pip-audit` on the lockfile.~~ **Done (0.3.5):** job `audit` in `.github/workflows/ci.yml`. Required on Protect Main. | Known CVEs in deps fail the build |
| 2 | ~~Enable GitHub private vulnerability reporting.~~ **Done:** matches `SECURITY.md`. | Matches SECURITY.md |
| 3 | ~~Dependabot for `pyproject.toml` / Actions.~~ **Done (0.3.5 / 0.4.0):** weekly uv + github-actions. `mcp>=1.0.0,<2.0.0` stays load-bearing (FastMCP removed in v2). Ignore `mcp` semver-major (PR #7 widened the range to `<3`). | `mcp` cannot silently float to 2.x |
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

Until D2-7 (wrap smoke) is done, do not call the MCP path fully smoked.
The README install command is sendable after D2-6.

---

## Sequence

```
D0-1..D0-5 (done; Protect Main requires lint + four tests + audit)  →  D1 (0.3.3)  →  D2 prep (0.3.5)  →  D2 publish (tag v0.4.0 + PyPI 0.4.0)  →  D2-6 (0.4.1 README/doctor pin)  →  D2-7 / D3-4 / D3-5
```

D0 code shipped on `main` as 0.3.2. **D1 shipped on `main` as 0.3.3**
(docs honesty). D2 prep landed in 0.3.5. **D2 publish landed:** tag
`v0.4.0`, PyPI 0.4.0, Trusted Publishing. **D2-6** is the README/doctor
pin (0.4.1). Stay Alpha. Local keychain injector, not a vault. Leftover:
D2-7 MCP smoke, D3-4 wrap-disable, D3-5 attestations link. Do not retag
0.4.0. Do not advertise unpinned `pip install` as the team command.

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
This D2 version PR sets **0.4.0** untagged. Do not tag until Nick’s
Release. Do not use major until 1.0.

---

## 1.0 (later, not this plan)

Keep 1.0 for product completeness (Windows CI, Homebrew optional, wrap-disable
default documented, no stale docs). Deployability is 0.4.0. Re-labeling to
1.0 without a published 0.4.x would repeat the 1.2.0 mistake.
