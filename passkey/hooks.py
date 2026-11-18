"""Pre-execution agent hook installer and validator for Claude Code, Cursor, and Gemini CLI."""

import json
import re
import shlex
import sys
from pathlib import Path

from .keychain import PasskeyError
from .mcp_config import load_config, save_config

SUPPORTED_HOOK_TOOLS = ("claude", "cursor", "gemini")

_SAFE_ENV_FILENAMES = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.passkey",
        ".env.schema",
        ".env.dist",
    }
)

_SENSITIVE_SUFFIXES = (".backup", ".enc", ".passkey")
_READ_SHELL_VERBS = frozenset(
    {
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "grep",
        "rg",
        "awk",
        "sed",
        "strings",
        "base64",
        "xxd",
        "hexdump",
        "od",
        "cp",
        "curl",
    }
)
_SHELL_SPLIT_RE = re.compile(r"(?:\|\||&&|[|;\n])")


def is_sensitive_secret_path(raw_path: str) -> bool:
    """Return True if raw_path targets a plaintext .env, .backup, or .enc bundle."""
    if not raw_path:
        return False
    cleaned = raw_path.strip().strip("'\"")
    if not cleaned:
        return False
    name = Path(cleaned).name
    lower_name = name.lower()
    if lower_name in _SAFE_ENV_FILENAMES:
        return False
    if lower_name == ".env" or (
        lower_name.startswith(".env.") and not lower_name.endswith((".example", ".sample", ".template", ".passkey"))
    ):
        return True
    return lower_name.endswith(_SENSITIVE_SUFFIXES)


def _check_shell_command(command: str) -> tuple[bool, str]:
    """Inspect a shell command string for secret-dumping patterns."""
    if not command or not command.strip():
        return True, ""

    for subcmd in _SHELL_SPLIT_RE.split(command):
        sub = subcmd.strip()
        if not sub:
            continue
        try:
            tokens = shlex.split(sub)
        except ValueError:
            tokens = sub.split()
        if not tokens:
            continue

        # Strip leading VAR=val assignments or sudo/env wrappers
        idx = 0
        while idx < len(tokens) and (
            "=" in tokens[idx] or tokens[idx] in ("env", "command", "nohup")
        ):
            idx += 1
        if idx >= len(tokens):
            continue

        exe = Path(tokens[idx]).name
        rest = tokens[idx + 1 :]

        # Block `passkey export` unless `--no-secrets` or `--encrypt` is present
        if (
            exe == "passkey"
            and rest
            and rest[0] == "export"
            and "--no-secrets" not in rest
            and "--encrypt" not in rest
        ):
            return (
                False,
                "Blocked by passkey hook: plaintext 'passkey export' is disallowed for AI agents.",
            )

        # Block shell file-reading utilities targeting .env, *.backup, *.enc
        if exe in _READ_SHELL_VERBS:
            for arg in rest:
                if arg.startswith("-"):
                    continue
                if is_sensitive_secret_path(arg):
                    return (
                        False,
                        f"Blocked by passkey hook: reading sensitive secret file '{arg}' is disallowed.",
                    )

    return True, ""


def evaluate_hook_payload(payload: dict) -> tuple[bool, str]:
    """Evaluate a PreToolUse / BeforeTool / Cursor hook JSON payload.

    Returns:
        (allowed, reason_if_blocked)
    """
    if not isinstance(payload, dict):
        return True, ""

    # Collect candidate file paths and commands across Claude, Cursor, and Gemini schemas
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    candidate_paths: list[str] = []
    for key in ("file_path", "path", "target_file", "filename"):
        for container in (payload, tool_input):
            val = container.get(key)
            if isinstance(val, str):
                candidate_paths.append(val)

    for path_str in candidate_paths:
        if is_sensitive_secret_path(path_str):
            return (
                False,
                f"Blocked by passkey hook: direct agent access to '{path_str}' is prohibited.",
            )

    candidate_commands: list[str] = []
    for key in ("command", "cmd", "command_line", "CommandLine"):
        for container in (payload, tool_input):
            val = container.get(key)
            if isinstance(val, str):
                candidate_commands.append(val)

    for cmd_str in candidate_commands:
        allowed, reason = _check_shell_command(cmd_str)
        if not allowed:
            return False, reason

    return True, ""


def run_hook_check(tool: str | None = None, stdin_text: str | None = None) -> int:
    """Read hook payload from stdin, emit tool-appropriate decision, and return exit code."""
    raw = sys.stdin.read() if stdin_text is None else stdin_text
    if not raw.strip():
        return 0

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return 0

    allowed, reason = evaluate_hook_payload(payload)
    normalized_tool = (tool or "").strip().lower()

    if allowed:
        if normalized_tool == "cursor":
            print(json.dumps({"permission": "allow"}))
        elif normalized_tool == "gemini":
            print(json.dumps({"decision": "allow"}))
        return 0

    if normalized_tool == "cursor":
        print(
            json.dumps(
                {
                    "permission": "deny",
                    "user_message": reason,
                    "agent_message": reason,
                }
            )
        )
        return 2

    if normalized_tool == "gemini":
        print(json.dumps({"decision": "deny", "reason": reason}))
        print(reason, file=sys.stderr)
        return 2

    # Claude Code (and generic fallback): exit code 2 with reason on stderr blocks tool execution
    print(reason, file=sys.stderr)
    return 2


def _hook_command_for(tool: str) -> str:
    return f"passkey hook check --tool {tool}"


def install_hook(tool: str, project_dir: Path | None = None) -> Path:
    """Non-destructively install passkey pre-execution guard hook for claude, cursor, or gemini."""
    normalized = tool.strip().lower()
    if normalized not in SUPPORTED_HOOK_TOOLS:
        raise PasskeyError(
            f"Unsupported hook tool '{tool}'. Choose one of: {', '.join(SUPPORTED_HOOK_TOOLS)}"
        )

    root = (project_dir or Path.cwd()).expanduser().resolve()
    cmd_str = _hook_command_for(normalized)

    if normalized == "claude":
        target = root / ".claude" / "settings.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        config = load_config(target) if target.exists() else {}
        hooks = config.setdefault("hooks", {})
        pre_list = hooks.setdefault("PreToolUse", [])
        already = any(
            isinstance(item, dict)
            and any(
                isinstance(h, dict) and h.get("command") == cmd_str
                for h in item.get("hooks", [])
            )
            for item in pre_list
        )
        if not already:
            pre_list.append(
                {
                    "matcher": "Bash|Read|Edit|MultiEdit|Write",
                    "hooks": [{"type": "command", "command": cmd_str}],
                }
            )
        save_config(config, target)
        return target

    if normalized == "cursor":
        target = root / ".cursor" / "hooks.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        config = load_config(target) if target.exists() else {"version": 1}
        config.setdefault("version", 1)
        hooks = config.setdefault("hooks", {})
        for event_name in ("beforeShellExecution", "beforeReadFile"):
            event_hooks = hooks.setdefault(event_name, [])
            if not any(
                isinstance(h, dict) and h.get("command") == cmd_str for h in event_hooks
            ):
                event_hooks.append({"command": cmd_str, "timeout": 10})
        save_config(config, target)
        return target

    # gemini
    target = root / ".gemini" / "settings.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    config = load_config(target) if target.exists() else {}
    hooks = config.setdefault("hooks", {})
    before_list = hooks.setdefault("BeforeTool", [])
    already = any(
        isinstance(item, dict)
        and any(
            isinstance(h, dict) and h.get("command") == cmd_str
            for h in item.get("hooks", [])
        )
        for item in before_list
    )
    if not already:
        before_list.append(
            {
                "matcher": ".*",
                "hooks": [
                    {
                        "name": "passkey-secret-guard",
                        "type": "command",
                        "command": cmd_str,
                    }
                ],
            }
        )
    save_config(config, target)
    return target
