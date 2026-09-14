## Summary

<!-- What changed and why. -->

## SemVer

- [ ] **patch** — fix / tests / CI / docs / chore
- [ ] **minor** — user-visible feature (or breaking change while 0.x)
- [ ] **major** — 1.0.0 only (do not use yet)

Version on this branch: `<!-- x.y.z -->` (must differ from `main`)

## Release notes

- [ ] `CHANGELOG.md` `[Unreleased]` updated (Added / Changed / Fixed / Security)
- [ ] `pyproject.toml` `[project] version` bumped (single source; `uv.lock` matches)

## Test plan

- [ ] `uv run pytest -q`
- [ ] `uv run ruff check passkey/ tests/`

## Agents

- [ ] `sys-release` ran
- [ ] `sys-review` ran (no Critical)
