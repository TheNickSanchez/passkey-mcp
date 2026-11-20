"""User settings stored in the passkey data dir (settings.json).

Supported settings:
- require_auth (bool, default False): opt-in OS auth prompt before interactive CLI commands.
- mcp_write_tools (bool, default True): allow mutating MCP server tools.
- mcp_browser_broker (bool, default False): enable opt-in passkey_cdp_autofill MCP tool.
- agent_session_lease_ttl (int, default 600): session lease TTL in seconds for policy='session'.
- default_policy (str, default 'session' on macOS with LAContext else 'allow'): default access
  policy inherited by newly created entries ('allow', 'session', or 'prompt').
"""

import contextlib
import json
import os
import tempfile
from pathlib import Path

from .auth import is_lacontext_available
from .dirs import get_data_dir
from .keychain import PasskeyError
from .models import VALID_POLICIES

# key -> (type, default; None means computed via _platform_default_policy())
_SETTINGS_SCHEMA: dict[str, tuple[type, object]] = {
    "require_auth": (bool, False),
    "mcp_write_tools": (bool, True),
    "mcp_browser_broker": (bool, False),
    "agent_session_lease_ttl": (int, 600),
    "default_policy": (str, None),
}


def _platform_default_policy() -> str:
    """Return 'session' on macOS when Touch ID / LAContext is available, else 'allow'."""
    return "session" if is_lacontext_available() else "allow"


def _settings_path() -> Path:
    return get_data_dir() / "settings.json"


def _normalize_key(key: str) -> str:
    """Accept CLI-style dashes (require-auth) for internal underscores."""
    return key.strip().lower().replace("-", "_")


def _read_raw_settings_dict() -> dict | None:
    """Return raw settings.json dict if present and valid JSON object, else None."""
    path = _settings_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def has_explicit_default_policy() -> bool:
    """Return True if settings.json explicitly records a valid default_policy choice."""
    data = _read_raw_settings_dict()
    if data is None or "default_policy" not in data:
        return False
    raw_val = data.get("default_policy")
    return isinstance(raw_val, str) and raw_val.strip().lower() in VALID_POLICIES


def load_settings() -> dict:
    """Load settings, falling back to defaults on missing/corrupt file."""
    platform_pol = _platform_default_policy()
    defaults = {
        k: (platform_pol if k == "default_policy" else default)
        for k, (_, default) in _SETTINGS_SCHEMA.items()
    }
    data = _read_raw_settings_dict()
    if data is None:
        return defaults
    for key, (typ, _) in _SETTINGS_SCHEMA.items():
        fallback = defaults[key]
        if key not in data:
            continue
        value = data[key]
        if typ is int and isinstance(value, bool):
            defaults[key] = fallback
        elif isinstance(value, typ):
            if key == "agent_session_lease_ttl" and (value <= 0 or value > 7 * 24 * 3600):
                defaults[key] = fallback
            elif key == "default_policy":
                norm_pol = value.strip().lower()
                defaults[key] = norm_pol if norm_pol in VALID_POLICIES else fallback
            else:
                defaults[key] = value
        else:
            defaults[key] = fallback
    return defaults


def get_setting(key: str):
    """Return a setting value by name (raises PasskeyError for unknown keys)."""
    key = _normalize_key(key)
    if key not in _SETTINGS_SCHEMA:
        raise PasskeyError(
            f"Unknown setting '{key}'. Known settings: {', '.join(sorted(_SETTINGS_SCHEMA))}"
        )
    return load_settings()[key]


def set_setting(key: str, value) -> None:
    """Persist a setting atomically (raises PasskeyError for unknown keys/bad types)."""
    key = _normalize_key(key)
    if key not in _SETTINGS_SCHEMA:
        raise PasskeyError(
            f"Unknown setting '{key}'. Known settings: {', '.join(sorted(_SETTINGS_SCHEMA))}"
        )
    typ, _ = _SETTINGS_SCHEMA[key]
    if (typ is int and isinstance(value, bool)) or not isinstance(value, typ):
        raise PasskeyError(f"Setting '{key}' must be of type {typ.__name__}")
    if key == "agent_session_lease_ttl" and (value <= 0 or value > 7 * 24 * 3600):
        raise PasskeyError(
            "Setting 'agent_session_lease_ttl' must be between 1s and 7d (604800s)."
        )
    if key == "default_policy":
        norm_pol = value.strip().lower()
        if norm_pol not in VALID_POLICIES:
            raise PasskeyError(
                f"Invalid policy '{value}'. Expected one of: {', '.join(sorted(VALID_POLICIES))}",
                error_code="INVALID_USAGE",
            )
        value = norm_pol

    had_explicit_pol = has_explicit_default_policy()
    settings = load_settings()
    settings[key] = value
    if key != "default_policy" and not had_explicit_pol:
        settings.pop("default_policy", None)

    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".settings-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(settings, indent=2) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def require_auth_enabled() -> bool:
    """True when the user has opted in to OS auth prompts for terminal use."""
    return bool(load_settings().get("require_auth", False))


def mcp_write_tools_enabled() -> bool:
    """True when mutating MCP server tools (e.g. passkey_wrap_server) are allowed."""
    return bool(load_settings().get("mcp_write_tools", True))


def mcp_browser_broker_enabled() -> bool:
    """True when the opt-in passkey_cdp_autofill MCP tool is enabled."""
    return bool(load_settings().get("mcp_browser_broker", False))


def get_agent_session_lease_ttl() -> int:
    """Return session lease TTL in seconds for entries with ``policy = 'session'``."""
    return int(load_settings().get("agent_session_lease_ttl", 600))


def get_default_policy() -> str:
    """Return the configured or platform-default policy for newly created entries."""
    return str(load_settings().get("default_policy", _platform_default_policy()))


def _parse_bool(raw: str) -> bool:
    raw = raw.strip().lower()
    if raw in ("on", "true", "yes", "1", "enable", "enabled"):
        return True
    if raw in ("off", "false", "no", "0", "disable", "disabled"):
        return False
    raise PasskeyError(f"Expected on/off, got '{raw}'")


def cmd_config(
    key: str | None = None,
    value: str | None = None,
    *,
    json_output: bool = False,
) -> None:
    """Show or update passkey settings.

    Usage:
        passkey config                      Show all settings
        passkey config require-auth         Show one setting
        passkey config require-auth on      Update a setting
    """
    if key is None:
        settings = load_settings()
        if json_output:
            print(json.dumps(settings, indent=2))
            return
        print("Passkey settings:")
        for name in sorted(settings):
            print(f"  {name.replace('_', '-')} = {settings[name]}")
        print()
        print("Change with: passkey config <name> <value>")
        return

    if value is None:
        current = get_setting(key)
        normalized = _normalize_key(key)
        if json_output:
            print(json.dumps({"key": normalized, "value": current}, indent=2))
            return
        print(f"{normalized.replace('_', '-')} = {current}")
        return

    normalized = _normalize_key(key)
    if normalized not in _SETTINGS_SCHEMA:
        raise PasskeyError(
            f"Unknown setting '{normalized}'. Known settings: {', '.join(sorted(_SETTINGS_SCHEMA))}"
        )
    typ, _ = _SETTINGS_SCHEMA[normalized]
    if typ is bool:
        parsed: object = _parse_bool(value)
    elif normalized == "agent_session_lease_ttl":
        from .leases import parse_ttl

        parsed = parse_ttl(value)
    elif normalized == "default_policy":
        norm_pol = value.strip().lower()
        if norm_pol not in VALID_POLICIES:
            raise PasskeyError(
                f"Invalid policy '{value}'. Expected one of: {', '.join(sorted(VALID_POLICIES))}",
                error_code="INVALID_USAGE",
            )
        parsed = norm_pol
    else:
        try:
            parsed = int(value)
        except ValueError as e:
            raise PasskeyError(f"Expected integer for '{normalized}', got '{value}'") from e

    set_setting(normalized, parsed)
    if json_output:
        print(json.dumps({"key": normalized, "value": parsed, "updated": True}, indent=2))
        return
    print(f"Set {normalized.replace('_', '-')} = {parsed}")
    if normalized == "require_auth" and parsed:
        print()
        print("Note: this only affects interactive terminal commands.")
        print("Headless paths (passkey run from MCP servers) never prompt;")
        print("they rely on the OS keychain's own access controls.")
