---
name: release-hygiene
description: >-
  Classify SemVer (major/minor/patch), promote the previous Unreleased heading
  into a dated ## 0.3.N, update CHANGELOG.md [Unreleased], and bump
  pyproject.toml and uv.lock on every passkey-mcp branch and PR.
  Use when finishing a feature, committing for a PR, pushing, or opening a pull
  request.
---

# Release hygiene

Every merge to `main` must include a changelog bullet **and** a version bump. The `sys-release` agent owns this; follow the same rules if you are the parent agent.

## Classify (0.x)

- **patch** — bugfix, tests, CI, docs, chore, behavior-neutral refactor
- **minor** — new CLI/MCP behavior, or a breaking change while still 0.x
- **major** — 1.0.0 only (do not use)

First published tag is **0.4.0** (`PLAN.md` D2). Until that PR, bump **0.3.x**.

## Edit

1. Ensure `## [Unreleased]` exists at the top of `CHANGELOG.md`. Put **this PR’s** one-sentence bullets there (Added / Changed / Fixed / Security).
2. **Promote the previous version.** If `[Unreleased]` still holds notes for the version now on `main`, move them to `## 0.3.N (YYYY-MM-DD)` below `[Unreleased]`. Do not leave two versions mixed under `[Unreleased]`. This is not the same as creating `## 0.4.0`.
3. Bump `[project] version` in `pyproject.toml` only. `passkey --version` reads `importlib.metadata.version("passkey-mcp")` — do not re-add a hardcoded string in `passkey/__init__.py`. Bump `uv.lock`’s `passkey-mcp` version to match (`uv lock` or the smallest edit; do not bump dependencies unless this PR is about them).
4. If CHANGELOG still lists 0.3.0 known issues that the rewrite fixed, delete those lines when you touch the file.

## Do not

Tag, `twine upload`, or move `[Unreleased]` into `## 0.4.0` except on the D2 release PR.

If `CHANGELOG.md` is unchanged vs `main`, the Cursor hook will deny `git push` and `gh pr create`.
