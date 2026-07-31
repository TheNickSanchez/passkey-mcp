"""User settings stored in the passkey data dir (settings.json).

Currently a single opt-in setting:

- require_auth (bool, default False): when enabled, interactive commands
  that read or modify secrets additionally prompt for OS authentication
  (sudo/polkit) before proceeding. Off by default because the primary
  protection is the OS keychain's own ACL, and because headless paths
  (``passkey run`` from an MCP server) cannot answer prompts.
"""

import json
import os
from pathlib import Path

from .dirs import get_data_dir
from .keychain import PasskeyError

# key -> (type, default)
_SETTINGS_SCHEMA: dict[str, tuple[type, object]] = {
    "require_auth": (bool, False),
}


def _settings_path() -> Path:
    return get_data_dir() / "settings.json"


def _normalize_key(key: str) -> str:
    """Accept CLI-style dashes (require-auth) for internal underscores."""
    return key.strip().lower().replace("-", "_")


def load_settings() -> dict:
    """Load settings, falling back to defaults on missing/corrupt file."""
    defaults = {k: default for k, (_, default) in _SETTINGS_SCHEMA.items()}
    path = _settings_path()
    if not path.exists():
        return defaults
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return defaults
    if not isinstance(data, dict):
        return defaults
    for key, (typ, default) in _SETTINGS_SCHEMA.items():
        value = data.get(key, default)
        defaults[key] = value if isinstance(value, typ) else default
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
    """Persist a setting (raises PasskeyError for unknown keys/bad types)."""
    key = _normalize_key(key)
    if key not in _SETTINGS_SCHEMA:
        raise PasskeyError(
            f"Unknown setting '{key}'. Known settings: {', '.join(sorted(_SETTINGS_SCHEMA))}"
        )
    typ, _ = _SETTINGS_SCHEMA[key]
    if not isinstance(value, typ):
        raise PasskeyError(f"Setting '{key}' must be of type {typ.__name__}")

    settings = load_settings()
    settings[key] = value

    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(settings, indent=2) + "\n")


def require_auth_enabled() -> bool:
    """True when the user has opted in to OS auth prompts for terminal use."""
    return bool(load_settings().get("require_auth", False))


def _parse_bool(raw: str) -> bool:
    raw = raw.strip().lower()
    if raw in ("on", "true", "yes", "1", "enable", "enabled"):
        return True
    if raw in ("off", "false", "no", "0", "disable", "disabled"):
        return False
    raise PasskeyError(f"Expected on/off, got '{raw}'")


def cmd_config(key: str | None = None, value: str | None = None) -> None:
    """Show or update passkey settings.

    Usage:
        passkey config                      Show all settings
        passkey config require-auth         Show one setting
        passkey config require-auth on      Update a setting
    """
    if key is None:
        settings = load_settings()
        print("Passkey settings:")
        for name in sorted(settings):
            print(f"  {name.replace('_', '-')} = {settings[name]}")
        print()
        print("Change with: passkey config <name> <value>")
        return

    if value is None:
        current = get_setting(key)
        print(f"{_normalize_key(key).replace('_', '-')} = {current}")
        return

    parsed = _parse_bool(value)
    set_setting(key, parsed)
    normalized = _normalize_key(key)
    print(f"Set {normalized.replace('_', '-')} = {parsed}")
    if normalized == "require_auth" and parsed:
        print()
        print("Note: this only affects interactive terminal commands.")
        print("Headless paths (passkey run from MCP servers) never prompt;")
        print("they rely on the OS keychain's own access controls.")
