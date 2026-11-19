[Home](Home.md) › Core Guides › **Managing Secrets**

---

# Managing Secrets

Day-to-day workflows for creating, browsing, editing, rotating, and backing up secrets in your OS keychain.

> **Security Note:** Secrets **never** belong in shell `argv` (where `ps` and `.zsh_history` record them). Always enter secret values through `passkey`'s masked interactive prompts or out-of-band native OS dialogs (`passkey request`).

---

## 1. Creating Entries (`passkey new`)

Pass the entry name directly (and optionally `--template`) to jump straight to field entry:

```bash
# Create 'stripe' and enter secret fields interactively
passkey new stripe

# Or pre-populate expected field names from a built-in service template
passkey new aws --template aws
```

### Interactive Masked Input Shortcuts

When `passkey` prompts for a secret value, it echoes `•` bullets alongside a live character counter so you can verify paste lengths without exposing credentials in terminal scrollback:

```text
  Entry: stripe
  Field name (empty to save & exit): STRIPE_SECRET_KEY
  Value for STRIPE_SECRET_KEY: •••••••••••••••••••••••••••••••• (32 chars)
    + STRIPE_SECRET_KEY  (32 chars, sk_t…9a2f)
  Field name (empty to save & exit): ⏎
Saved 'stripe' with 1 field(s)
```

| Keystroke / Input | Behavior |
| :--- | :--- |
| **`Ctrl+R` or `Tab`** | Temporarily reveals the typed value in place; **auto-remasks to `•` on `Enter`** so secrets never stay in scrollback. |
| **`Ctrl+U`** | Clears the entire current input buffer and resets the character counter to `0`. |
| **`Backspace` / `Delete`** | Removes the last character and updates the live character count. |
| **Single-step paste at `Field name:`** | If you copy an assignment line from a dashboard into your clipboard and paste it at the interactive `Field name:` prompt, `passkey` splits the key and value in memory, previews `(N chars, xx…yy)`, and never echoes the raw value. |
| **Empty `Enter` at `Field name:`** | Saves the entry immediately and exits once at least one field has been added. |

---

## 2. Secret `fields` vs. Non-Secret `config`

Every `Entry` separates sensitive credentials from non-sensitive configuration metadata:

| Storage Bucket | Examples | Masked on `stdout`/`stderr`? | Exposed in `--json` / MCP? | Injected by `passkey run`? |
| :--- | :--- | :--- | :--- | :--- |
| **`fields` (Secrets)** | `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`, `PASSWORD` | **Yes** (`<concealed by passkey>`) | Key **names** only (`fields`) | **Yes** |
| **`config` (Metadata)** | `ORIGIN`, `AWS_REGION`, `HOST`, `COOKIE_NAME` | No | Key **names** only (`config_keys`) | **Yes** |

You can add or edit both `fields` and `config` keys inside `passkey edit <entry>`.

---

## 3. Browsing, Copying & Reverse Lookup

```bash
# Fuzzy-match an entry and copy a field to clipboard (auto-clears after 30s)
passkey stripe
passkey get stripe

# Copy all secret fields as POSIX single-quoted env lines (auto-clears after 30s)
passkey get stripe --all

# List all entries (human table, names-only for scripts, or metadata JSON)
passkey list
passkey list --names-only
passkey list --json

# Reverse-lookup which entry stores an environment variable (exact + alias match)
passkey find STRIPE_SECRET_KEY GH_TOKEN
passkey find --from-file .env.example --json

# Inspect full non-sensitive metadata (fields, config_keys, policy, active lease)
passkey info stripe
passkey info stripe --json
```

---

## 4. Editing, Updating Single Fields, Rotating & Cloning

```bash
# Open interactive menu to add/update/delete fields, edit config, or rename entry
passkey edit stripe

# Upsert a single secret field via masked prompt (preserves all other fields & metadata)
passkey entry set-field stripe WEBHOOK_SECRET

# Rotate a secret field and stamp last_rotated
passkey entry rotate stripe STRIPE_SECRET_KEY

# Stamp last_rotated headlessly after rotating via external/out-of-band workflow
passkey entry rotate stripe --touch-only

# Clone an entry to a staging/dev variant
passkey entry clone stripe stripe_staging

# Verify required fields exist (exits 0 if all present, 1 if any missing)
passkey entry check stripe STRIPE_SECRET_KEY WEBHOOK_SECRET --json

# Generate a 32-char cryptographically random secret onto clipboard (30s auto-clear)
passkey entry generate --length 32

# Delete an entry (-y / --yes skips confirmation)
passkey delete stripe_staging --yes
```

---

## 5. Built-In & Custom Templates (`passkey entry template`)

`passkey` ships with templates for `github`, `aws`, `slack`, `openai`, `claude`, `codex`, `gemini`, `cursor-agent`, `wrangler`, `stripe`, `vercel`, `postgres`, and `mysql`:

```bash
# List all built-in and custom templates
passkey entry template list

# Inspect expected fields for a template
passkey entry template show aws

# Create a new entry guided by a template
passkey entry template apply github github_work

# Save an existing entry's field names (never values!) as a reusable custom template
passkey entry template add
```

---

## 6. Encrypted Backups & Imports (`AES-256-GCM` + `Scrypt`)

Transfer entries safely across machines using authenticated `PK01` encrypted bundles (`AES-256-GCM` with `Scrypt` `N=2^20, r=8, p=1`, 32-byte salt, 12-byte nonce, minimum 12-character passphrase, written with `O_EXCL` and `0o600` permissions):

```bash
# Export all entries to an encrypted bundle
passkey export backup.passkey.enc --encrypt

# Export specific entries only
passkey export prod-keys.enc --entries aws stripe --encrypt

# Export field names & metadata ONLY (zero secret values — safe for inventory)
passkey export inventory.json --no-secrets

# Preview an encrypted bundle import without writing to keychain
passkey import backup.passkey.enc --decrypt --dry-run

# Import an encrypted bundle (merges/preserves entry policy and metadata)
passkey import backup.passkey.enc --decrypt

# Import browser credentials from a Chrome CSV export (filter by domain prefix)
passkey import chrome-passwords.csv --mode chrome --filter github.com --insecure
```

> **Tip:** To share a **single** entry with a teammate using an auto-generated 8-word passphrase, see `passkey share` and `passkey receive` in [05 — Team Workflows](05-Team-Workflows.md).

---

[← Quickstart](01-Quickstart.md) · [Next: Running & Injecting →](03-Running-and-Injecting.md)
