[Home](Home.md) › Security & Advanced › **Browser Agent Autofill**

---

# Browser Agent Autofill (`CDP` Credential Broker)

Authenticate Playwright, Puppeteer, or browser-use AI agents into web dashboards via local Chrome DevTools Protocol (`CDP`) **without ever passing usernames, passwords, or session cookies through the LLM context window**.

---

## How It Works

```text
1. Browser Agent navigates tab to https://dashboard.example.com/login
2. Agent calls `passkey browser-fill portal_login --cdp-url ws://127.0.0.1:9222`
   (or MCP tool `passkey_cdp_autofill` when explicitly enabled)
3. passkey connects directly over loopback RFC-6455 WebSocket (ignores HTTP_PROXY)
4. Queries `window.location.origin` and enforces EXACT (scheme, host, port) match
   against `entry.config["ORIGIN"]` — aborts immediately on phishing/redirect mismatch!
5. Enforces entry policy (`allow`, `session`, or `prompt` Touch ID)
6. Injects USERNAME/EMAIL + PASSWORD via `Input.insertText` (and/or `SESSION_COOKIE`
   via `Network.setCookie`) directly into Chromium — LLM only sees `fields_injected`!
```

---

## Step 1: Create a Browser Entry with `ORIGIN`

Store the exact allowed login origin (`https://host[:port]`) in `config["ORIGIN"]` (or `fields["ORIGIN"]`) alongside any combination of `USERNAME`, `EMAIL`, `PASSWORD`, and/or `SESSION_COOKIE`:

```bash
# 1. Create the entry and enter PASSWORD (and/or USERNAME / SESSION_COOKIE)
passkey new portal_login

# 2. Open interactive editor -> Config -> set ORIGIN=https://dashboard.example.com
passkey edit portal_login

# 3. (Recommended) Gate browser login behind session or per-use Touch ID
passkey policy portal_login session
```

### Supported Browser Entry Keys

| Key Name | Bucket (`fields` or `config`) | Injection Mechanism |
| :--- | :--- | :--- |
| **`ORIGIN`** *(required)* | `config` *(preferred)* or `fields` | Verified against `window.location.origin` (`scheme + hostname + effective_port`). Non-HTTPS origins are rejected unless host is `localhost` / `127.0.0.1` / `::1`. |
| **`USERNAME`** / **`EMAIL`** | `fields` or `config` | Focuses matching username/email `<input>` and types via CDP `Input.insertText` (fires native `input` events for React/Vue forms). |
| **`PASSWORD`** | `fields` | Focuses enabled `input[type="password"]` and injects via CDP `Input.insertText` (fails closed if no password input is present). |
| **`SESSION_COOKIE`** | `fields` | Sets `HttpOnly` cookie via CDP `Network.setCookie` (`Secure=true` on HTTPS, `domain` locked to `ORIGIN` host). |
| **`COOKIE_NAME`** *(optional)* | `config` | Custom cookie name for `SESSION_COOKIE` (defaults to `"session"`). |

---

## Step 2: Launch Chromium/Chrome with Loopback Remote Debugging

Bind Chrome's debugging port strictly to loopback (`127.0.0.1`):

```bash
# macOS Google Chrome with an isolated automation profile
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --remote-debugging-port=9222 \
  --remote-debugging-address=127.0.0.1 \
  --user-data-dir="/tmp/chrome-agent-profile" \
  "https://dashboard.example.com/login"
```

---

## Step 3: Autofill via CLI (`passkey browser-fill`)

Once the active browser tab is on the login page, run:

```bash
# Root port URL automatically discovers the active page target via http://127.0.0.1:9222/json
passkey browser-fill portal_login --cdp-url ws://127.0.0.1:9222

# Or target a specific page WebSocket URL directly
passkey browser-fill portal_login --cdp-url ws://127.0.0.1:9222/devtools/page/ABCD1234
```

Output (secret-free):

```text
Autofilled USERNAME, PASSWORD on https://dashboard.example.com
```

---

## Step 4: Opt-In MCP Tool (`passkey_cdp_autofill`)

For safety, the MCP tool `passkey_cdp_autofill` is **disabled by default** (`mcp_browser_broker = false`). Enable it explicitly if you want MCP-connected browser agents to trigger autofill directly:

```bash
# Enable MCP browser autofill
passkey config mcp-browser-broker on

# Disable again when finished
passkey config mcp-browser-broker off
```

When invoked by an agent:

```json
{
  "entry_name": "portal_login",
  "cdp_url": "ws://127.0.0.1:9222"
}
```

Response returned to the LLM (zero credential values):

```json
{
  "filled": true,
  "origin": "https://dashboard.example.com",
  "fields_injected": ["USERNAME", "PASSWORD"]
}
```

> **Security Note:** `passkey` connects strictly to loopback hosts (`127.0.0.1`, `localhost`, `::1`) using a raw stdlib TCP socket that bypasses `HTTP_PROXY` / `HTTPS_PROXY`, preventing proxy-interception or remote CDP exfiltration attacks. After `passkey browser-fill` populates the fields, the browser agent simply clicks the page's Submit button.

---

[← Security & Biometrics](06-Security-and-Biometrics.md) · [Next: CLI Command Reference →](08-CLI-Command-Reference.md)
