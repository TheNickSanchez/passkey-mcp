"""Agent skill and rules installer for Claude Code, Cursor, Gemini CLI, and AGENTS.md."""

import contextlib
import os
import tempfile
from pathlib import Path

from .keychain import PasskeyError

SUPPORTED_SKILL_TOOLS = ("claude", "cursor", "gemini", "agents", "all")

AGENTS_MARKER_START = "<!-- passkey-agent-rules:start -->"
AGENTS_MARKER_END = "<!-- passkey-agent-rules:end -->"

_CORE_RULES_BODY = """\
## Passkey Secret Management Rules (AI Agents)

Secrets for this workspace are stored in the OS keychain via `passkey`—never in `.env` files, shell history, or chat transcripts.

### Golden Rules
1. **Never request raw secrets in chat:** Never ask the user to paste API keys, tokens, or passwords into the conversation. If an entry or field is missing, instruct the user to run `passkey new <entry>` or `passkey entry set-field <entry> <FIELD>` in their own terminal.
2. **Never run interactive commands:** Do not run bare `passkey`, `passkey new`, `passkey edit`, `passkey get`, or `passkey rotate` (without `--touch-only`). Pass `--no-input` if unsure.
3. **Inspect metadata via `--json` or MCP tools first:**
   - List entries: `passkey list --json` (or MCP `passkey_list`)
   - Inspect fields, `policy` (`allow` vs `prompt`), and `has_active_lease`: `passkey info <entry> --json` (or MCP `passkey_entry_info`)
   - Check required fields: `passkey check <entry> <FIELD...> --json`
   - Dry-run preflight before execution: `passkey run <entry> --dry-run --json -- <command>` (or MCP `passkey_preflight_run`)
4. **Inject secrets cleanly at runtime:**
   - Subprocess env injection: `passkey run -q --strict <entry> -- <command>`
   - Dotenv reference mapping: `passkey run -q --env-file .env.passkey -- <command>`
   - Gitignored template rendering: `passkey inject -i .env.template -o .env`
5. **Respect `prompt` policy & leases:** If `will_prompt_biometric` is `true`, ask the user to grant a scoped lease in their terminal before running headless loops:
   `passkey lease grant <entry> --ttl 15m`
"""

_CLAUDE_OR_GEMINI_SKILL = (
    "---\n"
    "name: passkey\n"
    "description: Safe OS-keychain secret discovery, preflight validation, and runtime injection "
    "with passkey without exposing secret values in chat or files.\n"
    "---\n\n"
    + _CORE_RULES_BODY
)

_CURSOR_RULE_MDC = (
    "---\n"
    "description: Safe OS-keychain secret management and runtime injection via passkey\n"
    "alwaysApply: true\n"
    "---\n\n"
    + _CORE_RULES_BODY
)


def _atomic_write_text(dest: Path, content: str, mode: int = 0o644) -> Path:
    """Atomically write text file using tempfile.mkstemp + os.replace."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dest.parent, prefix=".passkey-skill-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return dest


def _upsert_agents_md(agents_path: Path) -> Path:
    """Idempotently insert or update the bounded passkey rules block in AGENTS.md."""
    managed_block = f"{AGENTS_MARKER_START}\n{_CORE_RULES_BODY.rstrip()}\n{AGENTS_MARKER_END}\n"

    if not agents_path.exists():
        return _atomic_write_text(agents_path, f"# Agent Instructions\n\n{managed_block}")

    existing = agents_path.read_text(encoding="utf-8")
    if AGENTS_MARKER_START in existing and AGENTS_MARKER_END in existing:
        before, remainder = existing.split(AGENTS_MARKER_START, 1)
        _, after = remainder.split(AGENTS_MARKER_END, 1)
        updated = before + managed_block.rstrip("\n") + after
        if not updated.endswith("\n"):
            updated += "\n"
        return _atomic_write_text(agents_path, updated)

    sep = "" if existing.endswith("\n\n") else ("\n" if existing.endswith("\n") else "\n\n")
    return _atomic_write_text(agents_path, existing + sep + managed_block)


def install_skill(tool: str, project_dir: Path | None = None) -> list[Path]:
    """Install agent skill/instruction files for claude, cursor, gemini, agents, or all."""
    normalized = tool.strip().lower()
    if normalized not in SUPPORTED_SKILL_TOOLS:
        raise PasskeyError(
            f"Unsupported skill target '{tool}'. Choose one of: {', '.join(SUPPORTED_SKILL_TOOLS)}"
        )

    root = (project_dir or Path.cwd()).expanduser().resolve()
    targets = ("claude", "cursor", "gemini", "agents") if normalized == "all" else (normalized,)
    written: list[Path] = []

    for item in targets:
        if item == "claude":
            written.append(
                _atomic_write_text(
                    root / ".claude" / "skills" / "passkey" / "SKILL.md",
                    _CLAUDE_OR_GEMINI_SKILL,
                )
            )
        elif item == "cursor":
            written.append(
                _atomic_write_text(
                    root / ".cursor" / "rules" / "passkey.mdc",
                    _CURSOR_RULE_MDC,
                )
            )
        elif item == "gemini":
            written.append(
                _atomic_write_text(
                    root / ".gemini" / "skills" / "passkey" / "SKILL.md",
                    _CLAUDE_OR_GEMINI_SKILL,
                )
            )
        elif item == "agents":
            written.append(_upsert_agents_md(root / "AGENTS.md"))

    return written
