# Security Policy

## Product

Passkey is a local OS-keychain injector for MCP and CLI secrets. It moves
secrets out of config files into the OS keychain (`keyring`, service name
`passkey`). It is not a team vault, a password-manager vendor, or a
multi-tenant product. The project is Alpha, 0.x, and MIT-licensed.

Point InfoSec at the MIT license and this file (plus green CI and
required checks on protected `main`). This file does not claim
corporate approval.

## Reporting

1. Prefer GitHub private vulnerability reporting on
   [TheNickSanchez/passkey-mcp](https://github.com/TheNickSanchez/passkey-mcp).
   Reports there: aim to acknowledge within **7 days**.
2. Otherwise open a public issue that contains **no secrets** — no tokens,
   no bundle files, no env dumps, and no keychain exports.
3. There is no security email in this repository. Do not invent one.

## In scope

- Secret leakage via the CLI, MCP tools, doctor, audit, or
  export / import / share
- Local MCP config rewrite by `passkey_wrap_server` (local file write,
  not remote RCE)
- Keychain and index handling (`entries.json` is names only; values live
  in the OS keychain)
- `passkey run` environment injection (child-process env exposure)
- Docs and install commands that advertise an unpublished PyPI package

## Out of scope

- Multi-tenant vault, SSO, recovery, org admin, or cloud sync
- Physical access to an unlocked machine, root/admin compromise,
  keyloggers, or memory forensics
- Remote RCE or an external network attack surface (this product runs no
  remote server and makes no external network calls; `passkey browser-fill`
  connects strictly to loopback `127.0.0.1` / `localhost` Chrome DevTools
  when explicitly invoked)
- Corporate approval, SOC 2, or OWASP scorecards
- Windows extra-auth (documented no-op; see the threat model)

## Threat model

This section must match `passkey/auth.py`, `passkey/mcp_server.py`,
`passkey/keychain.py`, and `passkey/runner.py`.

Secrets never appear in argv. Interactive input uses `getpass`. Do not
document `KEY=VALUE` on the command line.

MCP tools (`passkey_list`, `passkey_fields`, `passkey_status`,
`passkey_doctor`, `passkey_wrap_server`, `passkey_validate_references`,
`passkey_audit_recent`, and opt-in `passkey_cdp_autofill`) return names,
field names, sanitized audit metadata, and status only — **never secret
values**.

`passkey run` injects env vars into a child process, scrubs resolved secret
values (`len >= 4`, raw UTF-8 and JSON-escaped) from child `stdout` and
`stderr` with `<concealed by passkey>` unless `--no-masking` is passed, and
is **never** gated by global `require-auth` so headless MCP servers with
default `allow` policy can start. See `cli/__init__.py` (`run` branch),
`runner.py`, and `masking.py`. Global extra auth (`passkey config require-auth on`)
applies to interactive CLI commands; per-entry `prompt` policy
(`passkey policy <entry> prompt`) optionally gates specific entries behind
out-of-band biometric/OS auth or an HMAC-signed lease (`passkey lease`).

Windows extra-auth is a documented no-op (`auth.py`
`_authenticate_windows` returns True). Protection is Credential Manager
ACLs alone. Linux extra-auth is `pkexec` with a getpass+sudo fallback.
macOS auth uses `LocalAuthentication.framework` (`LAContext` Touch ID /
Apple Watch / passcode) with a `sudo -v` fallback.

Primary protection is the OS keychain ACL via `keyring` (note: for editable
source/venv installs on macOS, Keychain ACLs bind to the underlying `python3`
binary). macOS Keychain ACLs (app prompt / login keychain) are the strong
case. Linux Secret Service and Windows Credential Manager are **best-effort**
by comparison; Linux also needs a running, unlocked keyring daemon.

The entry index `entries.json`, HMAC-chained `audit.log`, and HMAC-signed
`leases.json` (data dir) store metadata only, written at `0o600`. Secret
payloads and HMAC signing keys (`__audit_hmac_key__`, `__lease_hmac_key__`)
live in the OS keychain, not on disk.

`passkey_wrap_server` rewrites local MCP configs (`.json` / `.jsonc`, user
paths; it skips system prefixes including `/etc/`, `/private/etc/`, and
`/private/var/`). That is in scope as a **local config rewrite**, not remote
RCE, and can be disabled via `passkey config mcp-write-tools off` (D3-4).

`passkey run` prints a stderr warning unless `--quiet` is set: env vars can
be visible to other same-UID processes on the same machine. That is an
accepted, documented risk, not a hidden one.

There is no external network access and no telemetry. Supply chain **is**
the install path, published to PyPI via Trusted Publishing
(`uv tool install passkey-mcp` / `pipx install passkey-mcp`). Stay Alpha.

## What this file must not say

This policy does not say the product is “approved” or “approved for
corporate use.” It does not include SOC 2 or OWASP Top 10 scorecards,
“no known vulnerabilities,” invented dependency counts, or a fake
reviewer sign-off.
