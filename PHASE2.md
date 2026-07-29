# Phase 2 Plan: passkey-mcp

**Status**: Approved
**Scope**: 4 focused features — personal + team use
**Dependencies**: Minimal (no new major deps)
**Target**: Ship fast, iterate quickly

---

## Feature 1: `passkey generate` — Secret Generator

**Module**: `passkey/generator.py` (new)
**Command**: `passkey generate`

### What it does

Generates cryptographically secure passwords from the CLI, with clipboard support and integration into the entry creation flow.

### Commands

```
passkey generate                # Random password, 32 chars, copied to clipboard
passkey generate --length 48    # Custom length
passkey generate --no-copy      # Print only, don't copy
```

### Password generation algorithm

Borrowed from passkeys-cli (clean, proven pattern):
1. Pre-fill one char from each class: lowercase, uppercase, digit, symbol
2. Fill remaining length with `secrets.choice()` from full character set
3. Shuffle with `secrets.SystemRandom().shuffle()`
4. Return joined result

Character set: `string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"`

### Integration with `passkey new`

During interactive entry creation, after the user types a field name:
```
Field name: GITHUB_TOKEN
Generate a secure value? [y/N]:
  → If yes: generate and pre-fill (user can still edit)
  → If no: prompt for manual input as usual
```

### Dependencies

None — uses stdlib `secrets`.

---

## Feature 2: Secret Templates

**Module**: `passkey/templates.py` (new)
**Commands**: `passkey template list|show|apply|add`

### What it does

Pre-built field configurations for common services, so users don't have to remember which fields each service needs. Teams can standardize on shared templates.

### Commands

```
passkey template list                     # Show all templates
passkey template show github              # Show template details
passkey template apply github             # Create entry from template
passkey template apply github my-gh       # Create with custom name
passkey template add                      # Save current entry as template
```

### Built-in templates

| Template | Fields | Description |
|----------|--------|-------------|
| `github` | `GITHUB_TOKEN`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | GitHub personal access token / OAuth |
| `aws` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | AWS IAM credentials |
| `slack` | `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_SIGNING_SECRET` | Slack app / bot tokens |
| `openai` | `OPENAI_API_KEY` | OpenAI API access |
| `stripe` | `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`, `STRIPE_WEBHOOK_SECRET` | Stripe payment processing |
| `vercel` | `VERCEL_TOKEN` | Vercel deployment token |
| `postgres` | `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | PostgreSQL connection |
| `mysql` | `MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD` | MySQL connection |

### Template format

Each template is a Python dict:

```python
{
    "name": "github",
    "description": "GitHub personal access token or OAuth app",
    "fields": [
        {"name": "GITHUB_TOKEN", "description": "Personal access token (ghp_...)", "secret": True, "generate": True},
        {"name": "GITHUB_CLIENT_ID", "description": "OAuth app client ID", "secret": False},
        {"name": "GITHUB_CLIENT_SECRET", "description": "OAuth app client secret", "secret": True, "generate": True},
    ]
}
```

### Custom templates

- Saved to `~/.config/passkey/templates/<name>.json`
- Created via `passkey template add` (prompts for name, uses current entry's fields)
- Secret values are stripped — only field names and descriptions are saved
- Listed alongside built-in templates
- Custom templates override built-in ones (same name wins)

### Enhanced `passkey new` flow

Interactive mode only:
```
$ passkey new
Start from a template? [y/N]: y
? Select template: GitHub
Entry name (github): my-github
? GITHUB_TOKEN: (hidden) ****  [generated]
? GITHUB_CLIENT_ID: my-app-id
? GITHUB_CLIENT_SECRET: (hidden) ****  [generated]
✓ Created entry "my-github" with 3 fields
```

Non-interactive mode: unchanged (blank entry, fields added via `set-field`).

---

## Feature 3: Enhanced Team Sharing UX

**Module**: No new module — new commands in `passkey/commands.py`
**Commands**: `passkey share`, `passkey receive`

### What it does

Wraps the existing bundle export/import infrastructure with a cleaner, team-friendly workflow. The encryption and security are already solid; this is purely a UX layer.

### Commands

```
passkey share github                       # Interactive: select fields, set passphrase
passkey share github --output github.enc   # Export to specific file
passkey share --generate-passphrase        # Generate a 4-word passphrase for verbal sharing
passkey receive github.enc                 # Import: prompt for passphrase, preview, confirm
```

### `passkey share` workflow

```
$ passkey share github
? Fields to share: (Space to select, Enter to confirm)
  ◉ GITHUB_TOKEN
  ◉ GITHUB_CLIENT_SECRET
  ○ GITHUB_CLIENT_ID
? Create a passphrase for this bundle: ****
? Confirm passphrase: ****
? Your name (optional): alice
✓ Bundle exported to github-alice.enc (2 fields, 2.1 KB)
  Passphrase: correct-horse-battery-staple
  Share this passphrase separately — it cannot be recovered.
```

### `passkey receive` workflow

```
$ passkey receive github-alice.enc
? Passphrase: ****
? Import "github"? (2 fields from alice, shared 2026-07-27)
  → This will create a new entry "github"
  Proceed? [y/N]: y
✓ Imported "github" with 2 fields
  Fields: GITHUB_TOKEN, GITHUB_CLIENT_SECRET
```

### Passphrase generation

`passkey share --generate-passphrase` produces a 4-word passphrase using `secrets.choice` from a built-in 256-word list (~32 bits of entropy). Sufficient for sharing, easy to verbalize.

### Metadata in bundles

The bundle's encrypted payload includes optional metadata (backward-compatible):

```json
{
  "shared_by": "alice",
  "shared_at": "2026-07-27T10:30:00Z",
  "entries": [...]
}
```

Existing bundles without this metadata import normally.

### Error handling

`passkey share` on an entry with zero secret fields → error: "Entry 'X' has no secret fields to share."

---

## Feature 4: Secret Lifecycle + Health Dashboard

**Module**: `passkey/health.py` (new)
**Commands**: Enhanced `passkey doctor`, `passkey rotate`, `passkey audit`

### What it does

Gives users visibility into secret age, exposure, and health across their keychain and MCP tool configs.

### Commands

```
passkey doctor --deep                      # Extended diagnostics
passkey rotate github                      # Mark entry as rotated (timestamp only)
passkey audit --summary                    # Aggregate view
```

### Rotation tracking

Add optional `last_rotated` timestamp to entry metadata:

```json
{
  "_meta": {
    "format": 2,
    "created": "2026-07-27T10:00:00Z",
    "modified": "2026-07-27T12:00:00Z",
    "last_rotated": "2026-07-27T12:00:00Z",
    "source": "manual"
  }
}
```

- Set automatically on `passkey new` and `passkey rotate`
- Updated on `passkey edit` when a secret field value changes (detected via value comparison)
- Displayed in `passkey info` output
- `format` stays at 2 — `last_rotated` is additive, old code ignores unknown fields

### `passkey doctor --deep`

Extends existing `passkey doctor` with:

| Check | Description |
|-------|-------------|
| Entry age | Entries older than 90 days without rotation |
| Exposed secrets | MCP servers with plaintext secrets in config |
| Bundle permissions | Check for insecure bundle files (`.enc` with group/other perms) |
| Config health | Validate all detected MCP configs parse correctly |
| Duplicate fields | Same field name across multiple entries (flag only) |

Output example:
```
Passkey Doctor (deep)

✓ passkey found in PATH
✓ Keychain access working
✓ Claude Code config found
⚠ 3 entries older than 90 days (consider rotating)
✓ No exposed secrets in MCP configs
⚠ 1 bundle file has insecure permissions: github.enc (0o644)
✓ All MCP configs valid

Recommendations:
  • Rotate "github" (last rotated 120 days ago)
  • Rotate "aws-production" (last rotated 95 days ago)
  • Fix permissions: chmod 600 github.enc
```

### `passkey rotate`

```
$ passkey rotate github
✓ Marked "github" as rotated (2026-07-27T14:30:00Z)
```

Timestamp only. Use `passkey edit` to update secret values.

### `passkey audit --summary`

```
passkey audit --summary
  Operations (last 30 days):
    create:  12
    read:    45
    update:   8
    delete:   2
    export:   3
    import:   1

  Most accessed: github (15 reads)
  Oldest entry:  aws-production (created 2026-01-15)
```

### Dependencies

None — extends existing metadata and audit infrastructure.

---

## Test Coverage Additions

Embedded in each feature + filling existing gaps:

| Area | What to add |
|------|-------------|
| `passkey/generator.py` | Unit tests for generation, length validation, character diversity |
| `passkey/templates.py` | Built-in template integrity, custom template save/load, apply flow |
| `passkey share/receive` | Passphrase generation, simplified workflow, metadata handling |
| `passkey/health.py` | Rotation tracking, doctor --deep checks, audit summary |
| `auth.py` | Mocked tests for require_auth flow (macOS/Linux/fallback) |
| `mcp_commands.py` | Tests for cmd_init, cmd_status, cmd_doctor, cmd_servers, cmd_add |
| `importers.py` | Tests for import_mcp, import_chrome, import_auto, merge mode |
| `completion.py` | Validate generated scripts for syntax correctness |
| `commands.py` | Tests for cmd_check, cmd_set_field, cmd_export, cmd_audit |
| pyproject.toml | Add `[tool.coverage]` configuration |

---

## What we're NOT doing

| Rejected idea | Why |
|---------------|-----|
| PostgreSQL/database storage | Our keychain model is better (zero infra, hardware-backed) |
| Master password system | OS auth (Touch ID / sudo) is better |
| TUI dashboard | Overkill for CLI tool — doctor + audit summary covers it |
| Team roles/permissions | Too complex for focused phase |
| New major dependencies | Keeping footprint minimal; stdlib suffices for all 4 features |
| Web dashboard | Out of scope — CLI-first tool |
| API key / UUID generation types | Can be added later if needed; password covers 95% of use cases |
| Audit filters (--since, --entry) | Can be added later; --summary is enough for v1 |

---

## Implementation Order

1. **Feature 1: Generator** — smallest, self-contained, immediate value
2. **Feature 2: Templates** — builds on generator (templates can include `generate: true` fields)
3. **Feature 3: Share/Receive** — wraps existing infra, pure UX
4. **Feature 4: Health/Lifecycle** — extends metadata, most integration points
5. **Test coverage** — continuous throughout, final sweep at end

## Version

Bump to **1.2.0** after all 4 features merged.
