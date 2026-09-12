---
name: release-hygiene
description: >-
  Classify SemVer (major/minor/patch), update CHANGELOG.md [Unreleased], and bump
  pyproject.toml plus passkey/__init__.py on every passkey-mcp branch and PR.
  Use when finishing a feature, committing for a PR, pushing, or opening a pull request.
---

# Release hygiene

Every merge to `main` must include a changelog bullet **and** a version bump. The `sys-release` agent owns this; follow the same rules if you are the parent agent.

## Classify (0.x)

- **patch** — bugfix, tests, CI, docs, chore, behavior-neutral refactor
- **minor** — new CLI/MCP behavior, or a breaking change while still 0.x
- **major** — 1.0.0 only (do not use)

First published tag is **0.4.0** (`PLAN.md` D2). Until that PR, bump **0.3.x**.

## Edit

1. Ensure `## [Unreleased]` exists at the top of `CHANGELOG.md`. Add one sentence under Added / Changed / Fixed / Security.
2. Bump `[project] version` in `pyproject.toml` **and** `__version__` in `passkey/__init__.py` to the same value (until D2-5 single-sources metadata).
3. If CHANGELOG still lists 0.3.0 known issues that the rewrite fixed, delete those lines when you touch the file.

## Do not

Tag, `twine upload`, or move `[Unreleased]` into `## 0.4.0` except on the D2 release PR.

If `CHANGELOG.md` is unchanged vs `main`, the Cursor hook will deny `git push` and `gh pr create`.
