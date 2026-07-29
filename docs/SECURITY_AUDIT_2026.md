# Security Audit 2026 — Fix Plan

## Overview

Security audit performed Jul 28, 2026. Three parallel deep-dives covered:
secrets handling, MCP/imports, and cryptography.

- **2 MEDIUM** — should fix
- **6 LOW** — fix opportunistically
- Many positive findings (strong crypto, file perms, no secrets in MCP protocol)

## Priority Order

### MEDIUM

| # | Issue | Severity | File(s) | Status |
|---|-------|----------|---------|--------|
| M1 | Secrets visible in `ps` via CLI args (`set-field VALUE`, `add KEY=VALUE`) | MEDIUM | `cli.py:149,294`, `commands.py:401`, `mcp_commands.py:660` | ✅ Fixed |
| M2 | Arbitrary config path write via `passkey_wrap_server` | MEDIUM | `mcp_server.py:260-261` | ✅ Fixed |
| M3 | Unsanitized entry names in MCP error messages (log injection) | MEDIUM | `mcp_server.py:71,286` | ✅ Fixed |

### LOW

| # | Issue | Severity | File(s) | Status |
|---|-------|----------|---------|--------|
| L1 | Passphrase entropy ~32 bits (4 words × 256-word list) | LOW | `sharing.py:50` | ✅ Fixed |
| L2 | Crypto constants duplicated in sharing.py vs bundle.py | LOW | `sharing.py:187-191` | ✅ Fixed |
| L3 | Bundle import lacks permission checks | LOW | `bundle.py:145`, `sharing.py:240` | ✅ Fixed |
| L4 | Backup files inherit original (possibly insecure) permissions | LOW | `mcp_config.py:410` | ✅ Fixed |
| L5 | Audit log failures silently swallowed | LOW | `audit.py:60-62` | ✅ Fixed |
| L6 | Template name path injection in `save_custom_template()` public API | LOW | `templates.py:149-150` | ✅ Fixed |

## Verification

- `ruff check` — 0 lint errors
- `passkey --help` — grouped output intact
- All existing tests pass
- Specific feature smoke tests for each changed area
