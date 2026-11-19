"""Zero-config CLI wrapper plugins for AI coding agents and developer CLIs."""

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .audit import log_operation
from .dirs import ensure_data_dir, get_data_dir
from .keychain import PasskeyError, get_entry, list_entries
from .leases import authorize_entry_access
from .models import is_valid_name
from .runner import _run_masked_subprocess

try:
    import tomllib as _tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    _tomllib = None

VALID_PLUGIN_SCOPES = ("session", "dir", "global")

PLUGIN_SPECS: dict[str, dict] = {
    "claude": {
        "description": "Anthropic Claude Code CLI",
        "default_entry": "claude",
        "env_vars": ["ANTHROPIC_API_KEY"],
        "aliases": {"ANTHROPIC_API_KEY": ["ANTHROPIC_AUTH_TOKEN", "API_KEY", "TOKEN"]},
        "optional": set(),
    },
    "codex": {
        "description": "OpenAI Codex CLI",
        "default_entry": "openai",
        "env_vars": ["OPENAI_API_KEY"],
        "aliases": {"OPENAI_API_KEY": ["CODEX_API_KEY", "API_KEY", "TOKEN"]},
        "optional": set(),
    },
    "openai": {
        "description": "OpenAI CLI",
        "default_entry": "openai",
        "env_vars": ["OPENAI_API_KEY"],
        "aliases": {"OPENAI_API_KEY": ["API_KEY", "TOKEN"]},
        "optional": set(),
    },
    "gemini": {
        "description": "Google Gemini CLI",
        "default_entry": "gemini",
        "env_vars": ["GEMINI_API_KEY"],
        "aliases": {"GEMINI_API_KEY": ["GOOGLE_API_KEY", "API_KEY", "TOKEN"]},
        "optional": set(),
    },
    "cursor-agent": {
        "description": "Cursor background/CLI agent",
        "default_entry": "cursor-agent",
        "env_vars": ["CURSOR_API_KEY"],
        "aliases": {"CURSOR_API_KEY": ["API_KEY", "TOKEN"]},
        "optional": set(),
    },
    "gh": {
        "description": "GitHub CLI",
        "default_entry": "github",
        "env_vars": ["GH_TOKEN"],
        "aliases": {"GH_TOKEN": ["GITHUB_TOKEN", "PAT", "TOKEN"]},
        "optional": set(),
    },
    "aws": {
        "description": "AWS CLI",
        "default_entry": "aws",
        "env_vars": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
        "aliases": {},
        "optional": {"AWS_SESSION_TOKEN"},
    },
    "wrangler": {
        "description": "Cloudflare Wrangler CLI",
        "default_entry": "wrangler",
        "env_vars": ["CLOUDFLARE_API_TOKEN"],
        "aliases": {"CLOUDFLARE_API_TOKEN": ["CF_API_TOKEN", "API_TOKEN", "TOKEN"]},
        "optional": set(),
    },
    "vercel": {
        "description": "Vercel CLI",
        "default_entry": "vercel",
        "env_vars": ["VERCEL_TOKEN"],
        "aliases": {"VERCEL_TOKEN": ["API_TOKEN", "TOKEN"]},
        "optional": set(),
    },
    "stripe": {
        "description": "Stripe CLI",
        "default_entry": "stripe",
        "env_vars": ["STRIPE_SECRET_KEY"],
        "aliases": {"STRIPE_SECRET_KEY": ["STRIPE_API_KEY", "SECRET_KEY", "API_KEY"]},
        "optional": set(),
    },
}


def _env_override_var(cli_name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9]", "_", cli_name).upper()
    return f"PASSKEY_PLUGIN_{sanitized}"


def _global_plugins_path() -> Path:
    return get_data_dir() / "plugins.json"


def get_plugins_shell_path() -> Path:
    return get_data_dir() / "plugins.sh"


def _load_global_plugins() -> dict[str, str]:
    path = _global_plugins_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("plugins"), dict):
            return {
                str(k): str(v)
                for k, v in data["plugins"].items()
                if isinstance(k, str) and isinstance(v, str)
            }
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_global_plugins(mapping: dict[str, str]) -> Path:
    ensure_data_dir()
    path = _global_plugins_path()
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".plugins-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps({"version": 1, "plugins": mapping}, indent=2) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return path


def _parse_passkey_toml_plugins(toml_path: Path) -> dict[str, str]:
    """Parse [plugins] mapping from .passkey.toml using tomllib (with py310 fallback)."""
    content = toml_path.read_text(encoding="utf-8")
    if _tomllib is not None:
        try:
            parsed = _tomllib.loads(content)
            plugins = parsed.get("plugins", {})
            if isinstance(plugins, dict):
                return {
                    str(k): str(v)
                    for k, v in plugins.items()
                    if isinstance(k, str) and isinstance(v, str)
                }
        except Exception as e:
            raise PasskeyError(f"Invalid TOML in '{toml_path}': {e}") from e
        return {}

    # Minimal section parser for Python 3.10 where tomllib is not in stdlib
    in_plugins = False
    mapping: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_plugins = line[1:-1].strip() == "plugins"
            continue
        if in_plugins and "=" in line:
            k, v = line.split("=", 1)
            key = k.strip().strip("'\"")
            val = v.strip()
            if " #" in val:
                val = val.split(" #", 1)[0].strip()
            val = val.strip("'\"")
            if key and val:
                mapping[key] = val
    return mapping


def _write_passkey_toml_plugin(project_dir: Path, cli_name: str, entry_name: str) -> Path:
    """Create or update [plugins] binding in <project_dir>/.passkey.toml."""
    toml_path = project_dir / ".passkey.toml"
    existing = _parse_passkey_toml_plugins(toml_path) if toml_path.exists() else {}
    existing[cli_name] = entry_name

    lines = [
        "# Committable passkey plugin bindings (contains entry names only, never secrets)",
        "[plugins]",
    ]
    for k in sorted(existing):
        key_fmt = f'"{k}"' if "-" in k else k
        lines.append(f'{key_fmt} = "{existing[k]}"')

    content = "\n".join(lines) + "\n"
    fd, tmp_path = tempfile.mkstemp(dir=project_dir, prefix=".passkey-toml-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, toml_path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return toml_path


def _find_dir_plugin_binding(cli_name: str, start_dir: Path) -> tuple[str, Path] | None:
    """Walk upward from start_dir looking for .passkey.toml with [plugins].<cli_name>."""
    curr = start_dir.expanduser().resolve()
    home = Path.home().resolve()
    while True:
        candidate = curr / ".passkey.toml"
        if candidate.is_file():
            mapping = _parse_passkey_toml_plugins(candidate)
            if cli_name in mapping:
                return mapping[cli_name], candidate
        if curr == home or curr.parent == curr:
            break
        curr = curr.parent
    return None


def _write_shell_wrappers(active_clis: set[str]) -> Path:
    """Generate <data_dir>/plugins.sh defining shell wrapper functions."""
    ensure_data_dir()
    sh_path = get_plugins_shell_path()
    lines = [
        "# Generated by passkey plugin init — source in ~/.zshrc or ~/.bashrc",
    ]
    for cli in sorted(active_clis):
        if cli not in PLUGIN_SPECS:
            continue
        lines.append(f'{cli}() {{ command passkey plugin run {cli} -- "$@"; }}')
    content = "\n".join(lines) + "\n"
    fd, tmp_path = tempfile.mkstemp(dir=sh_path.parent, prefix=".plugins-sh-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, sh_path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return sh_path


def resolve_plugin_entry(cli_name: str, *, cwd: Path | None = None) -> tuple[str, str]:
    """Resolve (entry_name, source_label) for cli_name using session > dir > global > auto."""
    if cli_name not in PLUGIN_SPECS:
        raise PasskeyError(
            f"Unsupported plugin '{cli_name}'. Available plugins: {', '.join(sorted(PLUGIN_SPECS))}"
        )

    env_var = _env_override_var(cli_name)
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        if not is_valid_name(env_val):
            raise PasskeyError(f"Invalid entry name '{env_val}' in ${env_var}")
        return env_val, f"session (${env_var})"

    work_dir = cwd or Path.cwd()
    dir_hit = _find_dir_plugin_binding(cli_name, work_dir)
    if dir_hit is not None:
        bound_entry, toml_path = dir_hit
        if not is_valid_name(bound_entry):
            raise PasskeyError(f"Invalid entry name '{bound_entry}' in {toml_path}")
        return bound_entry, f"dir ({toml_path})"

    global_map = _load_global_plugins()
    if cli_name in global_map:
        bound_entry = global_map[cli_name]
        if not is_valid_name(bound_entry):
            raise PasskeyError(f"Invalid entry name '{bound_entry}' in plugins.json")
        return bound_entry, "global"

    # Auto fallback to cli_name or default_entry if present in keychain
    spec = PLUGIN_SPECS[cli_name]
    with contextlib.suppress(PasskeyError):
        existing = set(list_entries())
        if cli_name in existing:
            return cli_name, "auto"
        if spec["default_entry"] in existing:
            return spec["default_entry"], "auto"

    return spec["default_entry"], "default"


def list_plugins(cwd: Path | None = None) -> list[dict]:
    """List all built-in CLI plugins and their currently resolved keychain entry."""
    existing: set[str] = set()
    with contextlib.suppress(PasskeyError):
        existing = set(list_entries())

    items: list[dict] = []
    for cli_name in sorted(PLUGIN_SPECS):
        spec = PLUGIN_SPECS[cli_name]
        entry_name, source = resolve_plugin_entry(cli_name, cwd=cwd)
        items.append(
            {
                "cli": cli_name,
                "description": spec["description"],
                "env_vars": list(spec["env_vars"]),
                "entry": entry_name,
                "entry_exists": entry_name in existing,
                "source": source,
            }
        )
    return items


def init_plugin(
    cli_name: str,
    *,
    entry_name: str | None = None,
    scope: str = "global",
    project_dir: Path | None = None,
) -> dict:
    """Configure a CLI plugin binding at session, dir (.passkey.toml), or global scope."""
    if cli_name not in PLUGIN_SPECS:
        raise PasskeyError(
            f"Unsupported plugin '{cli_name}'. Available plugins: {', '.join(sorted(PLUGIN_SPECS))}"
        )
    if scope not in VALID_PLUGIN_SCOPES:
        raise PasskeyError(
            f"Invalid scope '{scope}'. Choose one of: {', '.join(VALID_PLUGIN_SCOPES)}"
        )

    spec = PLUGIN_SPECS[cli_name]
    chosen_entry = entry_name
    if not chosen_entry:
        with contextlib.suppress(PasskeyError):
            existing = set(list_entries())
            if cli_name in existing:
                chosen_entry = cli_name
            elif spec["default_entry"] in existing:
                chosen_entry = spec["default_entry"]
        if not chosen_entry:
            chosen_entry = spec["default_entry"]

    if not is_valid_name(chosen_entry):
        raise PasskeyError(f"Invalid entry name '{chosen_entry}'")

    global_map = _load_global_plugins()
    active_clis = set(global_map.keys()) | {cli_name}

    if scope == "session":
        env_var = _env_override_var(cli_name)
        snippet = (
            f"export {env_var}='{chosen_entry}'\n"
            f'{cli_name}() {{ command passkey plugin run {cli_name} -- "$@"; }}'
        )
        return {
            "cli": cli_name,
            "entry": chosen_entry,
            "scope": "session",
            "snippet": snippet,
        }

    if scope == "dir":
        root = (project_dir or Path.cwd()).expanduser().resolve()
        toml_path = _write_passkey_toml_plugin(root, cli_name, chosen_entry)
        sh_path = _write_shell_wrappers(active_clis)
        log_operation("plugin_init", chosen_entry, details={"mode": f"dir:{cli_name}"})
        return {
            "cli": cli_name,
            "entry": chosen_entry,
            "scope": "dir",
            "config_path": str(toml_path),
            "shell_path": str(sh_path),
        }

    # global
    global_map[cli_name] = chosen_entry
    cfg_path = _save_global_plugins(global_map)
    sh_path = _write_shell_wrappers(set(global_map.keys()))
    log_operation("plugin_init", chosen_entry, details={"mode": f"global:{cli_name}"})
    return {
        "cli": cli_name,
        "entry": chosen_entry,
        "scope": "global",
        "config_path": str(cfg_path),
        "shell_path": str(sh_path),
    }


def _build_plugin_env(cli_name: str, entry) -> tuple[dict[str, str], list[str]]:
    """Map entry fields/config onto canonical plugin environment variables."""
    spec = PLUGIN_SPECS[cli_name]
    combined = entry.get_all_env_vars()
    injected: dict[str, str] = dict(combined)
    secrets_to_mask: list[str] = list(entry.fields.values())

    aliases: dict[str, list[str]] = spec["aliases"]
    optional_vars: set[str] = spec["optional"]

    missing_required: list[str] = []
    for target_var in spec["env_vars"]:
        if injected.get(target_var):
            continue
        matched_val = None
        matched_is_secret = False
        for alt_key in aliases.get(target_var, []):
            if entry.fields.get(alt_key):
                matched_val = entry.fields[alt_key]
                matched_is_secret = True
                break
            if entry.config.get(alt_key):
                matched_val = entry.config[alt_key]
                break
        if matched_val is not None:
            injected[target_var] = matched_val
            if matched_is_secret:
                secrets_to_mask.append(matched_val)
        elif target_var not in optional_vars:
            missing_required.append(target_var)

    if missing_required:
        raise PasskeyError(
            f"Entry '{entry.name}' is missing required credential field(s) for '{cli_name}': "
            f"{', '.join(missing_required)}",
            error_code="MISSING_FIELD",
            entry=entry.name,
            missing_fields=missing_required,
            remediation_command=f"passkey entry set-field {entry.name} {missing_required[0]}",
        )

    return injected, secrets_to_mask


def run_plugin(
    cli_name: str,
    cli_args: list[str],
    *,
    entry_name: str | None = None,
    no_masking: bool = False,
    cwd: Path | None = None,
    executable_override: str | None = None,
) -> int:
    """Resolve plugin binding, enforce entry policy, map credentials, and execute with masking."""
    if cli_name not in PLUGIN_SPECS:
        raise PasskeyError(
            f"Unsupported plugin '{cli_name}'. Available plugins: {', '.join(sorted(PLUGIN_SPECS))}",
            error_code="INVALID_USAGE",
        )

    resolved_entry_name = entry_name
    if not resolved_entry_name:
        resolved_entry_name, _ = resolve_plugin_entry(cli_name, cwd=cwd)

    entry = get_entry(resolved_entry_name)
    if entry is None:
        raise PasskeyError(
            f"Passkey entry '{resolved_entry_name}' for plugin '{cli_name}' was not found.",
            error_code="ENTRY_NOT_FOUND",
            entry=resolved_entry_name,
            remediation_command=f"passkey new {resolved_entry_name}",
        )

    authorize_entry_access(entry, operation=f"run plugin '{cli_name}'")
    plugin_vars, secret_values = _build_plugin_env(cli_name, entry)

    exe = executable_override or shutil.which(cli_name)
    if not exe:
        raise PasskeyError(
            f"CLI executable '{cli_name}' was not found in PATH.",
            error_code="COMMAND_NOT_FOUND",
        )

    env = os.environ.copy()
    env.update(plugin_vars)
    cmd = [exe, *cli_args]

    log_operation("plugin_run", entry.name, details={"mode": cli_name}, argv0=cli_name)
    if no_masking:
        return subprocess.run(cmd, env=env).returncode
    return _run_masked_subprocess(cmd, env, secret_values)
