# passkey-mcp — Agent Notes

## Environment

- **Python**: 3.14+
- **Package manager**: `uv` (not pip)
- **Installed for CLI**: `pipx install --force -e .` (reinstall after any change)
- **Test venv**: `uv sync` creates `.venv/` at project root

## Testing

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/test_sharing.py -v

# Run full suite (282 tests)
uv run pytest --timeout=120
```

Test config is in `pyproject.toml` under `[tool.pytest.ini_options]`. The `uv.lock` pins all dependencies including test tools.

## Common Pitfalls

1. **Test first in `.venv`, not pipx**. Make changes, then `uv sync` + `uv run pytest` to validate. Only reinstall with pipx after tests pass.

2. **`passkey` CLI fails with `ModuleNotFoundError: No module named 'mcp.server.fastmcp'`** — means `mcp>=2.0.0` is installed. Pin `mcp>=1.0.0,<2.0.0` in `pyproject.toml` and reinstall. `FastMCP` was removed in v2.

3. **After checking out a branch**, you must either:
   - `pipx install --force -e /path/to/project` to use the branch's code via the CLI
   - Or use `uv run python -c "from passkey.cli import main"` for one-off validation

4. **`ruff check` fails format imports** — use `pipx run ruff check --fix` to auto-fix. `ruff` isn't in the uv dev deps by default (but should be added: `uv add --dev ruff`).

5. **Test file imports fail with `ModuleNotFoundError`** — check that `uv sync` ran and the required packages (like `keyring`, `mcp<2.0.0`, `cryptography`) are in `.venv`.

## Branch Workflow

```bash
git checkout -b feature-branch
# ... make changes ...
uv run pytest                       # validate
uv sync                             # update lockfile if deps changed
git add -A && git commit -m "msg"   # commit
git push -u origin feature-branch   # push
# PR → merge to main
git checkout main
git merge feature-branch
git push
git branch -d feature-branch
git push origin --delete feature-branch
```

## Security Patterns (established in this audit)

- **Secrets never in argv**: always prompt via `getpass.getpass()` instead of positional args.
- **Path validation**: block `/etc/`, `/dev/`, `/proc/`, `/sys/`, `/bin/`, `/sbin/`, `/usr/`, `/lib/`, `/boot/`, `/System/` for config file operations.
- **Error messages**: sanitize user-controlled strings (`re.sub(r"[^a-zA-Z0-9._\-\s]", "", s)`) before interpolation.
- **Permissions**: `0o600` on config files, `0o700` on directories.
- **Crypto**: AES-256-GCM, scrypt(N=2^20, r=8, p=1), fresh `os.urandom` salt+nonce per operation.
- **Import constants**: share crypto constants across modules (don't redefine).

## Key Files

| File | Purpose |
|------|---------|
| `passkey/cli.py` | CLI entry point, argparse, subcommand grouping |
| `passkey/mcp_server.py` | MCP server, FastMCP tools, path validation |
| `passkey/bundle.py` | Encrypted bundle export/import, crypto constants |
| `passkey/sharing.py` | Share/receive UX, passphrase generation |
| `passkey/keychain.py` | OS keychain via `keyring` |
| `passkey/models.py` | `Entry` dataclass, name validation regex |
| `passkey/mcp_config.py` | MCP config adapters, backup, atomic save |
| `passkey/mcp_commands.py` | CLI handlers for init/status/doctor/add |
| `passkey/audit.py` | Audit logging |
| `tests/` | 282 tests (pytest) |
