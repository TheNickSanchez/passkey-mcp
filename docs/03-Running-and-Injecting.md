[Home](Home.md) › Core Guides › **Running & Injecting**

---

# Running & Injecting Secrets

Five ways to deliver credentials from your OS keychain into apps, test suites, templates, and developer CLIs—without leaving plaintext `.env` files on disk.

---

## Which Injection Mode Should I Use?

| Mode | Best For | Writes to Disk? | Masks `stdout`/`stderr`? |
| :--- | :--- | :--- | :--- |
| **`passkey exec -- <cmd>`** | Day-to-day repo commands (`pytest`, `npm run dev`) with `.env.passkey` / `.passkey.toml` | No | **Yes** |
| **`passkey run <entry> -- <cmd>`** | Ad-hoc commands, scripts, and wrapped MCP servers | No | **Yes** |
| **`passkey plugin init <cli>`** | Everyday developer CLIs (`gh`, `aws`, `stripe`, `vercel`, `wrangler`, `claude`, `codex`, `gemini`) | Shell wrapper only | **Yes** |
| **`passkey mount <entry>`** | Legacy tools/SDKs that hardcode reading a `.env` file path | Ephemeral `0o600` FIFO pipe (0 bytes on disk) | N/A |
| **`passkey inject -i tpl -o out`** | Tools requiring a rendered config file (`docker-compose`, JSON/YAML configs) | Gitignored `0o600` file | N/A |

---

## 1. Subprocess Env Injection (`passkey run`)

`passkey run` loads every field (and `config` key) from one or more entries, injects them into the child process's environment, and scrubs secret values (`len >= 4`, both raw UTF-8 and JSON-escaped variants, even across OS pipe chunk boundaries) from child `stdout` and `stderr`:

```bash
# Inject a single entry
passkey run stripe -- pytest

# Inject multiple entries (later entries win on key collisions)
passkey run postgres stripe resend -- python manage.py test

# Quiet + strict mode (recommended for scripts and AI agents)
passkey run -q --strict stripe -- pytest -q

# Dry-run preflight: validate entries, passkey:// refs, Touch ID leases, and binary PATH
passkey run stripe --dry-run --json -- pytest

# Disable stream masking ONLY when child stdout emits raw binary data
passkey run --no-masking aws -- ./custom-binary > archive.bin
```

---

## 2. Zero-Config Repo Execution (`passkey exec`)

Once a repository has a committable `.env.passkey` or `.passkey.toml` manifest (created via `passkey project init`), neither you nor your AI agent ever needs to remember entry names again:

```bash
# One-time bootstrap from .env.example (writes .env.passkey with passkey:// pointers)
passkey project init

# Run from repo root OR any nested subdirectory up to the .git root
passkey exec -q -- pytest
passkey exec -- npm run build

# Preflight readiness & HMAC manifest trust check without spawning the child command
passkey exec --dry-run --json
```

> **Security Note:** `passkey exec` verifies the manifest's SHA-256 against an HMAC-signed trust store (`<data_dir>/trusted_projects.json`). Cloning an untrusted repo or modifying `.env.passkey` / `.passkey.toml` triggers a one-time Touch ID / OS approval prompt before any secret is loaded.

---

## 3. `passkey://` Reference URIs & Template Rendering (`passkey inject`)

Reference individual fields across different entries—and rename environment variables cleanly—using `passkey://<entry>/<field>` URIs. Entry names also support `$VAR` / `${VAR}` environment interpolation:

```ini
# .env.passkey (safe to commit — zero secret values)
DATABASE_URL=passkey://postgres_${APP_ENV}/DATABASE_URL
STRIPE_SECRET_KEY=passkey://stripe/STRIPE_SECRET_KEY
EMAIL_FROM_API_KEY=passkey://resend/API_KEY
```

Load a reference file directly into `passkey run`:

```bash
APP_ENV=staging passkey run -q --env-file .env.passkey -- python app.py
```

Or render `{{ passkey://entry/field }}` placeholders into a `0o600` gitignored config file using `passkey inject`:

```yaml
# config.tmpl.yaml (committable template)
database:
  url: "{{ passkey://postgres_dev/DATABASE_URL }}"
stripe:
  webhook_secret: "{{ passkey://stripe/WEBHOOK_SECRET }}"
```

```bash
# Atomic 0o600 render — refuses non-gitignored output paths inside git repos!
passkey inject -i config.tmpl.yaml -o config.local.yaml

# Overwrite an existing rendered file atomically
passkey inject -i config.tmpl.yaml -o config.local.yaml --force
```

---

## 4. Ephemeral POSIX FIFO `.env` Mounts (`passkey mount`)

Some frameworks insist on opening `.env` from disk. `passkey mount` creates a `0o600` named pipe (`mkfifo`), streams `KEY='value'` lines directly from memory when your app reads `.env`, and automatically unlinks the FIFO on exit, timeout, `SIGINT`, or `SIGTERM`—zero secret bytes ever touch your SSD:

```bash
# Serve exactly one read with a 30-second safety timeout, then auto-unlink .env
passkey mount stripe postgres --path .env --once --timeout 30 -q

# Serve up to 3 reads (e.g., multi-worker startup) with a 60-second timeout
passkey mount stripe --path .env --max-reads 3 --timeout 60
```

> **Tip:** Headless/agent invocations of `passkey mount` **must** include `--timeout <seconds>` (alongside `--once` or `--max-reads`) so an unread FIFO never blocks indefinitely.

---

## 5. Zero-Config CLI Plugins (`passkey plugin`)

Keep `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `ANTHROPIC_API_KEY`, and `OPENAI_API_KEY` out of `~/.zshrc` permanently by binding developer CLIs to keychain entries:

```bash
# Bind GitHub CLI ('gh') globally to your 'github' keychain entry
passkey plugin init gh

# Add the generated shell wrapper functions once to ~/.zshrc or ~/.bashrc
echo 'source "$HOME/Library/Application Support/passkey/plugins.sh"' >> ~/.zshrc
# (On Linux: source "$HOME/.local/share/passkey/plugins.sh")
```

Supported built-in CLI plugins (`passkey plugin list --json`):

| CLI | Default Entry | Injected Env Var(s) | Accepted Field Aliases |
| :--- | :--- | :--- | :--- |
| `claude` | `claude` | `ANTHROPIC_API_KEY` | `ANTHROPIC_AUTH_TOKEN`, `API_KEY`, `TOKEN` |
| `codex` | `openai` | `OPENAI_API_KEY` | `CODEX_API_KEY`, `API_KEY`, `TOKEN` |
| `openai` | `openai` | `OPENAI_API_KEY` | `API_KEY`, `TOKEN` |
| `gemini` | `gemini` | `GEMINI_API_KEY` | `GOOGLE_API_KEY`, `API_KEY`, `TOKEN` |
| `cursor-agent` | `cursor-agent` | `CURSOR_API_KEY` | `API_KEY`, `TOKEN` |
| `gh` | `github` | `GH_TOKEN` | `GITHUB_TOKEN`, `PAT`, `TOKEN` |
| `aws` | `aws` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` *(opt)* | — |
| `wrangler` | `wrangler` | `CLOUDFLARE_API_TOKEN` | `CF_API_TOKEN`, `API_TOKEN`, `TOKEN` |
| `vercel` | `vercel` | `VERCEL_TOKEN` | `API_TOKEN`, `TOKEN` |
| `stripe` | `stripe` | `STRIPE_SECRET_KEY` | `STRIPE_API_KEY`, `SECRET_KEY`, `API_KEY` |

### Scoped Plugin Overrides (`session > dir > global > auto`)

```bash
# Repo-scoped binding in .passkey.toml [plugins] (committable — overrides global)
passkey plugin init aws --entry aws_staging --scope dir

# Current-shell override snippet (highest precedence)
eval "$(passkey plugin init gh --entry github_personal --scope session)"

# Direct invocation without shell functions
passkey plugin run gh -- pr status
```

---

[← Managing Secrets](02-Managing-Secrets.md) · [Next: Onboarding AI Agents →](04-AI-Agent-Onboarding.md)
