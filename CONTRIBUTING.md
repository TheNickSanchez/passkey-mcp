# Contributing

passkey-mcp is a local OS-keychain injector for MCP/CLI secrets, not a
team vault. Alpha, 0.x. Agent profiles (`sys-arch`, `sys-engineer`,
`sys-release`, `sys-review`) and landmines live in [AGENTS.md](AGENTS.md).

## Develop

Python 3.10+. Use **uv only** — not pip.

```bash
uv sync
uv run pytest -q
uv run ruff check passkey/ tests/
```

## Pull requests

- Do **not** commit to `main`. Open a branch and a PR.
- Add a changelog note under `[Unreleased]` in `CHANGELOG.md`.
- Version bumps are `sys-release`'s job on the same branch before the PR.
