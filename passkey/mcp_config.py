"""MCP configuration management for multiple AI tools.

Provides an adapter-based system to read, analyze, and rewrite
MCP server configurations across different AI coding tools
(Claude, Gemini, VS Code, Cursor, OpenCode, Windsurf, Cline, Zed).
"""

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .dirs import ensure_data_dir

BACKUP_SUFFIX = ".backup"


# ---------------------------------------------------------------------------
# Secret detection heuristics (shared across all tools)
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "KEY",
    "CREDENTIAL",
    "AUTH",
    "API_KEY",
    "PRIVATE",
    "CLIENT_ID",
    "TENANT_ID",
    "ACCESS_KEY",
    "REFRESH_TOKEN",
]

NON_SECRET_SUFFIXES = [
    "PAGE_ID",
    "BOARD_ID",
    "SPACE_ID",
    "GROUP_ID",
    "PROJECT_ID",
    "SPRINT_ID",
    "RUNBOOK_ID",
]

NON_SECRET_VARS = {
    "PYTHONPATH",
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "PYTHONUNBUFFERED",
    "MCP_TOOL_MODE",
    "NODE_ENV",
    "LANG",
    "LC_ALL",
    "TERM",
    "EDITOR",
    "VISUAL",
    "PWD",
    "OLDPWD",
    "TMPDIR",
    "XDG_CONFIG_HOME",
}


_SECRET_VALUE_REGEXES = (
    re.compile(r"://[^/\s:@]+:[^/\s@]+@"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{12,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{6,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+"),
)


def is_likely_secret(var_name: str) -> bool:
    """Determine if an env var name likely contains a secret."""
    if var_name in NON_SECRET_VARS:
        return False
    upper = var_name.upper()
    if any(suffix in upper for suffix in NON_SECRET_SUFFIXES):
        return False
    return any(pattern in upper for pattern in SECRET_PATTERNS)


def is_likely_secret_value(value: object) -> bool:
    """Detect embedded credentials or well-known API token prefixes in an env value."""
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped or stripped.startswith("passkey://"):
        return False
    return any(rx.search(stripped) for rx in _SECRET_VALUE_REGEXES)


def extract_secrets(env: dict) -> tuple[dict, dict]:
    """Split env vars into secrets and non-secrets."""
    secrets = {}
    non_secrets = {}
    for key, value in env.items():
        if isinstance(value, str) and value.strip().startswith("passkey://"):
            non_secrets[key] = value
        elif is_likely_secret(key) or (
            key not in NON_SECRET_VARS and is_likely_secret_value(value)
        ):
            secrets[key] = value
        else:
            non_secrets[key] = value
    return secrets, non_secrets


# ---------------------------------------------------------------------------
# Tool adapter definition
# ---------------------------------------------------------------------------


class MCPConfigError(Exception):
    """Raised when MCP configuration has issues."""

    pass


@dataclass
class ToolAdapter:
    """Defines how to find and rewrite MCP configs for a specific tool."""

    name: str
    display_name: str
    root_key: str
    env_key: str = "env"
    command_is_array: bool = False
    supports_project_config: bool = False
    project_config_name: str = ""
    # Populated by _build_platform_paths
    global_paths: dict[str, Path] = field(default_factory=dict)
    project_paths: dict[str, Path] = field(default_factory=dict)

    def get_global_path(self) -> Path | None:
        """Return the global config path for the current platform."""
        return self.global_paths.get(sys.platform)

    def get_project_path(self) -> Path | None:
        """Return the project-level config path for the current platform."""
        return self.project_paths.get(sys.platform) if self.supports_project_config else None

    def get_all_existing_paths(self) -> list[Path]:
        """Return all config paths that exist on disk."""
        paths = []
        global_path = self.get_global_path()
        if global_path and global_path.exists():
            paths.append(global_path)
        project_path = self.get_project_path()
        if project_path and project_path.exists():
            paths.append(project_path)
        return paths


def _claude_paths() -> tuple[dict, dict]:
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return {"win32": appdata / "Claude" / "claude.json"}, {}
    if sys.platform == "linux":
        xdg = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
        return {"linux": xdg / "claude" / "claude.json"}, {}
    return {"darwin": Path.home() / ".claude.json"}, {}


def _claude_desktop_paths() -> tuple[dict, dict]:
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return {"win32": appdata / "Claude" / "claude_desktop_config.json"}, {}
    if sys.platform == "linux":
        return {"linux": Path.home() / ".config" / "Claude" / "claude_desktop_config.json"}, {}
    return {
        "darwin": Path.home()
        / "Library"
        / "Application Support"
        / "Claude"
        / "claude_desktop_config.json"
    }, {}


def _gemini_paths() -> tuple[dict, dict]:
    if sys.platform == "win32":
        home = Path.home()
        return {"win32": home / ".gemini" / "settings.json"}, {
            "win32": Path(".gemini") / "settings.json"
        }
    return {
        "darwin": Path.home() / ".gemini" / "settings.json",
        "linux": Path.home() / ".gemini" / "settings.json",
    }, {
        "darwin": Path(".gemini") / "settings.json",
        "linux": Path(".gemini") / "settings.json",
    }


def _vscode_paths() -> tuple[dict, dict]:
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return {"win32": appdata / "Code" / "User" / "mcp.json"}, {
            "win32": Path(".vscode") / "mcp.json"
        }
    if sys.platform == "linux":
        xdg = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
        return {"linux": xdg / "Code" / "User" / "mcp.json"}, {
            "linux": Path(".vscode") / "mcp.json"
        }
    return {
        "darwin": Path.home() / "Library" / "Application Support" / "Code" / "User" / "mcp.json",
    }, {"darwin": Path(".vscode") / "mcp.json"}


def _cursor_paths() -> tuple[dict, dict]:
    if sys.platform == "win32":
        home = Path.home()
        return {"win32": home / ".cursor" / "mcp.json"}, {"win32": Path(".cursor") / "mcp.json"}
    return {
        "darwin": Path.home() / ".cursor" / "mcp.json",
        "linux": Path.home() / ".cursor" / "mcp.json",
    }, {
        "darwin": Path(".cursor") / "mcp.json",
        "linux": Path(".cursor") / "mcp.json",
    }


def _opencode_paths() -> tuple[dict, dict]:
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return {"win32": appdata / "opencode" / "opencode.json"}, {"win32": Path("opencode.json")}
    if sys.platform == "linux":
        xdg = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
        return {"linux": xdg / "opencode" / "opencode.json"}, {"linux": Path("opencode.json")}
    return {
        "darwin": Path.home() / ".config" / "opencode" / "opencode.json",
    }, {"darwin": Path("opencode.json")}


def _windsurf_paths() -> tuple[dict, dict]:
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return {"win32": appdata / "Codeium" / "Windsurf" / "mcp_config.json"}, {}
    return {
        "darwin": Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
        "linux": Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
    }, {}


def _cline_paths() -> tuple[dict, dict]:
    base = Path("Code") / "User" / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return {"win32": appdata / base / "cline_mcp_settings.json"}, {}
    if sys.platform == "linux":
        xdg = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
        return {"linux": xdg / base / "cline_mcp_settings.json"}, {}
    return {
        "darwin": Path.home()
        / "Library"
        / "Application Support"
        / base
        / "cline_mcp_settings.json",
    }, {}


def _zed_paths() -> tuple[dict, dict]:
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
        return {"win32": appdata / "Zed" / "settings.json"}, {
            "win32": Path(".zed") / "settings.json"
        }
    return {
        "darwin": Path.home() / ".config" / "zed" / "settings.json",
        "linux": Path.home() / ".config" / "zed" / "settings.json",
    }, {
        "darwin": Path(".zed") / "settings.json",
        "linux": Path(".zed") / "settings.json",
    }


def _make_adapter(
    name: str,
    display_name: str,
    root_key: str,
    path_fn,
    env_key: str = "env",
    command_is_array: bool = False,
    supports_project_config: bool = False,
    project_config_name: str = "",
) -> ToolAdapter:
    global_paths, project_paths = path_fn()
    return ToolAdapter(
        name=name,
        display_name=display_name,
        root_key=root_key,
        env_key=env_key,
        command_is_array=command_is_array,
        supports_project_config=supports_project_config,
        project_config_name=project_config_name,
        global_paths=global_paths,
        project_paths=project_paths,
    )


ADAPTERS: dict[str, ToolAdapter] = {
    "claude": _make_adapter("claude", "Claude Code", "mcpServers", _claude_paths),
    "claude_desktop": _make_adapter(
        "claude_desktop", "Claude Desktop", "mcpServers", _claude_desktop_paths
    ),
    "gemini": _make_adapter(
        "gemini",
        "Gemini CLI",
        "mcpServers",
        _gemini_paths,
        supports_project_config=True,
        project_config_name=".gemini/settings.json",
    ),
    "vscode": _make_adapter(
        "vscode",
        "VS Code",
        "servers",
        _vscode_paths,
        supports_project_config=True,
        project_config_name=".vscode/mcp.json",
    ),
    "cursor": _make_adapter(
        "cursor",
        "Cursor",
        "mcpServers",
        _cursor_paths,
        supports_project_config=True,
        project_config_name=".cursor/mcp.json",
    ),
    "opencode": _make_adapter(
        "opencode",
        "OpenCode",
        "mcp",
        _opencode_paths,
        env_key="environment",
        command_is_array=True,
        supports_project_config=True,
        project_config_name="opencode.json",
    ),
    "windsurf": _make_adapter("windsurf", "Windsurf", "mcpServers", _windsurf_paths),
    "cline": _make_adapter("cline", "Cline", "mcpServers", _cline_paths),
    "zed": _make_adapter(
        "zed",
        "Zed",
        "context_servers",
        _zed_paths,
        supports_project_config=True,
        project_config_name=".zed/settings.json",
    ),
}

# ---------------------------------------------------------------------------
# Config file I/O
# ---------------------------------------------------------------------------


def _strip_jsonc_comments(content: str) -> str:
    """Remove // and /* */ comments without touching string literals.

    A regex cannot tell `// comment` apart from `"https://…"`; this small
    state machine tracks whether we are inside a JSON string.
    """
    out = []
    i = 0
    n = len(content)
    in_string = False
    while i < n:
        ch = content[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:  # keep escape sequences intact
                out.append(content[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = content[i + 1]
            if nxt == "/":
                while i < n and content[i] != "\n":
                    i += 1
                continue
            if nxt == "*":
                i += 2
                while i + 1 < n and not (content[i] == "*" and content[i + 1] == "/"):
                    i += 1
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def load_config(path: Path) -> dict:
    """Load and parse an MCP config file (JSON or JSONC).

    Args:
        path: Path to config file

    Returns:
        Parsed config dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        MCPConfigError: If config is invalid
    """
    if not path.exists():
        raise FileNotFoundError(f"Config not found at {path}")

    content = path.read_text()

    # Try standard JSON first
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Try stripping comments (JSONC support for OpenCode, Zed, etc.)
    try:
        return json.loads(_strip_jsonc_comments(content))
    except json.JSONDecodeError as e:
        raise MCPConfigError(f"Invalid JSON in {path}: {e}") from e


def save_config(config: dict, path: Path) -> None:
    """Save config to file atomically.

    Uses write-to-temp + os.replace to prevent corruption on crash.
    """
    content = json.dumps(config, indent=2) + "\n"
    fd, tmp_path = tempfile.mkstemp(
        dir=path.parent,
        prefix=".passkey-tmp-",
        suffix=".json",
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def is_file_exposed_in_git(path: Path) -> bool:
    """Return True if path resides inside a git working tree and is not gitignored."""
    expanded = path.expanduser()
    parent = expanded.parent if str(expanded.parent) else Path(".")
    try:
        resolved_parent = parent.resolve()
    except OSError:
        resolved_parent = parent

    target = resolved_parent / expanded.name
    try:
        inside = subprocess.run(
            ["git", "-C", str(resolved_parent), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if inside.returncode != 0 or inside.stdout.strip().lower() != "true":
            return False

        ignored = subprocess.run(
            ["git", "-C", str(resolved_parent), "check-ignore", "-q", str(target)],
            capture_output=True,
            timeout=5,
        )
        # returncode 0 => path is ignored (safe); non-zero => not ignored (exposed)
        return ignored.returncode != 0
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False


def get_backups_dir() -> Path:
    """Return the isolated backups directory inside the passkey data dir."""
    backups_dir = ensure_data_dir() / "backups"
    backups_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            backups_dir.chmod(0o700)
    return backups_dir


def backup_config(path: Path, backup_path: Path | None = None) -> Path:
    """Create a 0o600 backup of an MCP config file.

    By default, backups are stored in <data_dir>/backups/ with a timestamp so
    plaintext pre-migration secrets are never left inside workspace directories.
    """
    if backup_path is not None:
        target = backup_path.expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
    else:
        ts = datetime.now().strftime("%Y%m%dT%H%M%S%f")
        target = get_backups_dir() / f"{path.name}.{ts}{BACKUP_SUFFIX}"
    shutil.copy2(path, target)
    target.chmod(0o600)
    return target


# ---------------------------------------------------------------------------
# Server-level operations
# ---------------------------------------------------------------------------


def get_mcp_servers(config: dict, adapter: ToolAdapter) -> dict:
    """Extract MCP servers from config using the adapter's root key."""
    return config.get(adapter.root_key, {})


def set_mcp_servers(config: dict, adapter: ToolAdapter, servers: dict) -> None:
    """Set MCP servers in config using the adapter's root key."""
    config[adapter.root_key] = servers


def get_env_from_server(server_config: dict, adapter: ToolAdapter) -> dict:
    """Extract environment variables from a server config."""
    return server_config.get(adapter.env_key, {})


def set_env_on_server(server_config: dict, adapter: ToolAdapter, env: dict) -> None:
    """Set environment variables on a server config."""
    if env:
        server_config[adapter.env_key] = env
    elif adapter.env_key in server_config:
        del server_config[adapter.env_key]


def is_passkey_wrapped(server_config: dict) -> bool:
    """Check if a server config already uses passkey wrapper."""
    command = server_config.get("command", "")
    if isinstance(command, str):
        return command == "passkey" or command.endswith("/passkey")
    # Handle array commands (OpenCode style)
    if isinstance(command, list) and command:
        return command[0] == "passkey" or (
            isinstance(command[0], str) and command[0].endswith("/passkey")
        )
    return False


def get_wrapped_entry_name(server_config: dict) -> str | None:
    """Extract the primary passkey entry name from a wrapped server config.

    Supports both standard string-command configs (args=["run", ...]) and
    array-command configs (command=["passkey", "run", ...]), ignoring run flags
    such as -q/--quiet, --no-masking, and --env-file.
    """
    if not is_passkey_wrapped(server_config):
        return None

    tokens: list[str] = []
    args = server_config.get("args", [])
    command = server_config.get("command", "")

    if isinstance(args, list) and args and args[0] == "run":
        tokens = [str(t) for t in args[1:]]
    elif isinstance(command, list) and len(command) >= 2 and command[1] == "run":
        tokens = [str(t) for t in command[2:]]
    else:
        return None

    if "--" in tokens:
        tokens = tokens[: tokens.index("--")]

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-q", "--quiet", "--no-masking"):
            i += 1
            continue
        if tok == "--env-file":
            i += 2
            continue
        if tok.startswith("--env-file="):
            i += 1
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return tok
    return None


def rewrite_server_for_passkey(
    server_name: str,
    server_config: dict,
    adapter: ToolAdapter,
) -> dict:
    """Transform server config to use passkey wrapper.

    Handles differences between tool formats (string vs array commands,
    different env keys, etc.).
    """
    new_config = {}

    # Preserve type if present
    if "type" in server_config:
        new_config["type"] = server_config["type"]

    if adapter.command_is_array:
        # OpenCode style: command is an array
        new_config["command"] = ["passkey", "run", "--quiet", server_name, "--"]
        original_command = server_config.get("command", [])
        if isinstance(original_command, list):
            new_config["command"].extend(original_command)
        new_config["args"] = server_config.get("args", [])
    else:
        # Standard style: command is a string, args is a list
        original_command = server_config.get("command", "")
        original_args = server_config.get("args", [])
        new_config["command"] = "passkey"
        new_config["args"] = [
            "run",
            "--quiet",
            server_name,
            "--",
            original_command,
            *list(original_args),
        ]

    # Extract and keep non-secret env vars
    env = get_env_from_server(server_config, adapter)
    if env:
        _, non_secrets = extract_secrets(env)
        if non_secrets:
            set_env_on_server(new_config, adapter, non_secrets)

    return new_config


def get_original_command(server_config: dict) -> tuple[str, list[str]]:
    """Extract the original command from a passkey-wrapped config.

    Handles standard form (command="passkey", args=["run", NAME, "--", cmd,
    ...]) and array form (command=["passkey", "run", NAME, "--", cmd, ...]
    with original args preserved in "args").
    """
    args = list(server_config.get("args", []))

    # Standard form: original command + args live after "--" in args.
    if "--" in args:
        sep_idx = args.index("--")
        original_cmd = args[sep_idx + 1] if len(args) > sep_idx + 1 else ""
        original_args = args[sep_idx + 2 :] if len(args) > sep_idx + 2 else []
        return original_cmd, original_args

    # Array form (OpenCode style): original command lives after "--" in the
    # command array; original "args" were preserved separately and are NOT
    # part of the returned tuple.
    command = server_config.get("command", "")
    if isinstance(command, list) and "--" in command:
        sep_idx = command.index("--")
        tail = command[sep_idx + 1 :]
        original_cmd = tail[0] if tail else ""
        return original_cmd, tail[1:]

    return "", []


def restore_server_from_passkey(
    server_config: dict,
    adapter: ToolAdapter,
    secrets: dict | None = None,
) -> dict:
    """Rebuild an inline server config from its passkey-wrapped form.

    The inverse of rewrite_server_for_passkey: restores the original
    command/args and carries over env vars. Secret values are only written
    back when explicitly passed via the secrets argument.

    Args:
        server_config: The passkey-wrapped server config
        adapter: Tool adapter (controls command shape and env key)
        secrets: Optional secret fields to restore into env

    Returns:
        Restored inline server config
    """
    new_config = {}

    if "type" in server_config:
        new_config["type"] = server_config["type"]

    original_cmd, original_args = get_original_command(server_config)

    if adapter.command_is_array:
        # Rebuild the original command array; original "args" were kept
        # separate by the wrap and are carried over unchanged.
        new_config["command"] = [original_cmd, *original_args] if original_cmd else []
        preserved_args = server_config.get("args", [])
        if preserved_args:
            new_config["args"] = list(preserved_args)
    else:
        new_config["command"] = original_cmd
        if original_args:
            new_config["args"] = original_args

    env = dict(get_env_from_server(server_config, adapter))
    if secrets:
        env.update(secrets)
    set_env_on_server(new_config, adapter, env)

    return new_config


def get_server_security_status(
    server_name: str,
    server_config: dict,
    passkey_entries: list[str],
    adapter: ToolAdapter,
) -> dict:
    """Determine the security status of an MCP server."""
    result = {
        "server": server_name,
        "status": "unknown",
        "passkey_entry": None,
        "exposed_secrets": [],
        "non_secret_env": [],
    }

    if is_passkey_wrapped(server_config):
        entry_name = get_wrapped_entry_name(server_config)
        if entry_name:
            result["passkey_entry"] = entry_name

            if entry_name not in passkey_entries:
                result["status"] = "broken"
            else:
                env = get_env_from_server(server_config, adapter)
                secrets, non_secrets = extract_secrets(env)
                result["exposed_secrets"] = list(secrets.keys())
                result["non_secret_env"] = list(non_secrets.keys())
                result["status"] = "partial" if secrets else "secured"
    else:
        env = get_env_from_server(server_config, adapter)
        secrets, non_secrets = extract_secrets(env)
        result["exposed_secrets"] = list(secrets.keys())
        result["non_secret_env"] = list(non_secrets.keys())
        result["status"] = "exposed" if secrets else "no_secrets"

    return result


def find_passkey_command() -> str | None:
    """Find the passkey command in PATH."""
    return shutil.which("passkey")


def get_all_config_paths() -> list[tuple[str, Path]]:
    """Return all existing MCP config paths with their tool names.

    Returns:
        List of (tool_name, path) tuples for configs that exist on disk
    """
    results = []
    for name, adapter in ADAPTERS.items():
        for path in adapter.get_all_existing_paths():
            results.append((name, path))
    return results


def find_adapter_for_path(path: Path) -> ToolAdapter | None:
    """Find which tool adapter a config path belongs to."""
    for adapter in ADAPTERS.values():
        for platform_path in adapter.global_paths.values():
            if path == platform_path or path.resolve() == platform_path.resolve():
                return adapter
        for platform_path in adapter.project_paths.values():
            if path == platform_path or path.resolve() == platform_path.resolve():
                return adapter
    return None
