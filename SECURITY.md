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
- Remote RCE or a network attack surface (this product has no server and
  makes no network calls)
- Corporate approval, SOC 2, or OWASP scorecards
- Windows extra-auth (documented no-op; see the threat model)

## Threat model

This section must match `passkey/auth.py`, `passkey/mcp_server.py`,
`passkey/keychain.py`, and `passkey/runner.py`.

Secrets never appear in argv. Interactive input uses `getpass`. Do not
document `KEY=VALUE` on the command line.

MCP tools (`passkey_list`, `passkey_fields`, `passkey_status`,
`passkey_doctor`, `passkey_wrap_server`) return names, field names, and
status only — **never secret values**.

`passkey run` injects env vars into a child process and is **never**
extra-auth-gated, so headless MCP servers can start. See `cli/__init__.py`
(`run` branch) and `runner.py`. Extra sudo/pkexec is opt-in
(`passkey config require-auth on`) and applies only to interactive CLI
commands. It never applies to `run`.

Windows extra-auth is a documented no-op (`auth.py`
`_authenticate_windows` returns True). Protection is Credential Manager
ACLs alone. Linux extra-auth is `pkexec` with a getpass+sudo fallback.
macOS extra-auth is `sudo -v` (Touch ID if pam_tid is configured).

Primary protection is the OS keychain ACL via `keyring`. macOS Keychain
ACLs (app prompt / login keychain) are the strong case. Linux Secret
Service and Windows Credential Manager are **best-effort** by comparison;
Linux also needs a running, unlocked keyring daemon.

The entry index `entries.json` (data dir) is names only, written atomically
at `0o600`. Secret payloads are keychain items, not that file.

`passkey_wrap_server` rewrites local MCP configs (`.json` / `.jsonc`, user
paths; it skips a short list of system prefixes). That is in scope as a
**local config rewrite**, not remote RCE. An optional later control is
D3-4 (disable write tools) — not this release.

`passkey run` prints a stderr warning: env vars can be visible to other
processes on the same machine. That is an accepted, documented risk, not
a hidden one.

There is no network and no telemetry. Supply chain **is** the install
path. First installable release is PyPI **0.4.0** via Trusted Publishing
(`pipx install passkey-mcp==0.4.0`). Stay Alpha.

## What this file must not say

This policy does not say the product is “approved” or “approved for
corporate use.” It does not include SOC 2 or OWASP Top 10 scorecards,
“no known vulnerabilities,” invented dependency counts, or a fake
reviewer sign-off.
