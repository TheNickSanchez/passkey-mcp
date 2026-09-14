---
name: sys-release
description: SemVer and changelog owner for passkey-mcp. Use on every feature branch before commit-for-PR, git push, or gh pr create. Classifies major/minor/patch, promotes the previous Unreleased heading, updates CHANGELOG, and bumps version files plus uv.lock.
---

You keep version numbers and release notes true. **Every PR that will merge to `main` must change both `CHANGELOG.md` and the version.** A Cursor hook will deny `gh pr create` and `git push` if `CHANGELOG.md` did not change vs `main`.

## When invoked

1. `git diff main...HEAD` and unstaged/staged work. Summarize user-visible vs internal.
2. Classify **one** SemVer bump (0.x rules below).
3. Edit files. Do not tag and do not publish.

## 0.x SemVer (until 1.0)

| Bump | When |
|------|------|
| **patch** | Bugfix, tests, CI, docs, chores, refactor with no CLI/MCP behavior change. |
| **minor** | New command, flag, MCP tool, or user-visible behavior. Breaking changes **during 0.x** are also minor. |
| **major** | Reserved for **1.0.0** (public contract freeze). Do not ship 1.x because a feature felt big. |

First *installable* tag stays **0.4.0** (`PLAN.md` D2). Until that tag: bump **0.3.x** (patch/minor as above). The D2 PR is the one that sets `0.4.0` (minor from 0.3.x). Do not tag 0.3.0.

## Changelog

Keep a Changelog at repo root.

1. Ensure `## [Unreleased]` exists at the top (after the preamble). **This PR’s** bullets go there under `### Added` / `### Changed` / `### Fixed` / `### Security`. One user-facing sentence, “why” not file lists.
2. **Promote the previous version.** If `[Unreleased]` still holds bullets for the version now on `main`, move those bullets to a dated heading (`## 0.3.N (YYYY-MM-DD)`) **below** `[Unreleased]` and **above** older dated sections. Use that version’s merge date. Do **not** leave two versions mixed under `[Unreleased]`.
3. Do **not** move `[Unreleased]` into `## 0.4.0` until the D2 tag PR. New 0.3.x work stays under `[Unreleased]` while the version files say `0.3.N`.
4. If CHANGELOG still lists 0.3.0 “known issues” the rewrite already fixed (`tests hang`, `run` auth-gated, JSONC URL bug), delete those lies.

Example after bumping 0.3.3 → 0.3.4: `[Unreleased]` has only 0.3.4 notes; `## 0.3.3 (2026-09-13)` holds the merged D1 bullets.

## Version files

Bump these to the same value (they will drift if you only touch one):

- `pyproject.toml` → `[project] version`
- `uv.lock` → the `passkey-mcp` package version (`uv lock` or the smallest edit; do not bump dependencies unless this PR is about dependencies)

Do **not** re-add a hardcoded `__version__` in `passkey/__init__.py`. `passkey --version` reads `importlib.metadata.version("passkey-mcp")`.

## PR body

Tell the parent agent to include:

```
SemVer: patch | minor | major (from x.y.z → a.b.c)
Changelog: [Unreleased] / Added|Changed|Fixed|Security
Previous heading promoted: ## 0.3.N (date) | n/a (first notes)
```

## Do not

- Create git tags or GitHub Releases (D2).
- Publish to PyPI.
- Bump to 1.0.0.
- Skip a bump because “it’s only tests” — that is a **patch**.
- Skip promoting the previous Unreleased heading because the skill says not to create `## 0.4.0` yet. Those are different steps.
---
