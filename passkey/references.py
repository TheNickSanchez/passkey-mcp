"""Structured secret reference URIs (passkey://<entry>/<field>) and template injection."""

import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path

from .keychain import PasskeyError, _get_entry, get_entry
from .models import Entry, is_valid_name

REFERENCE_SCHEME = "passkey://"
_ENV_INTERP_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_FIELD_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$")
_TEMPLATE_PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*(passkey://(?:(?!\}\})\S)+)\s*\}\}")
_BARE_REFERENCE_PATTERN = re.compile(r"passkey://(?:(?!\}\})[^\s\"'])+")


def is_reference(value: object) -> bool:
    """Return True if value is a passkey:// reference string."""
    return isinstance(value, str) and value.strip().startswith(REFERENCE_SCHEME)


def _interpolate_entry_segment(raw_entry: str, env: Mapping[str, str]) -> str:
    """Expand $VAR / ${VAR} strictly inside the entry segment."""
    if "$" not in raw_entry:
        return raw_entry

    # Verify every '$' in raw_entry belongs to a valid $VAR or ${VAR} token
    cursor = 0
    parts: list[str] = []
    for match in _ENV_INTERP_PATTERN.finditer(raw_entry):
        literal = raw_entry[cursor : match.start()]
        if "$" in literal:
            raise PasskeyError(f"Invalid variable syntax in secret reference entry '{raw_entry}'")
        parts.append(literal)
        var_name = match.group(1) or match.group(2)
        val = env.get(var_name)
        if not val:
            raise PasskeyError(
                f"Environment variable '{var_name}' is not set for secret reference"
            )
        parts.append(val)
        cursor = match.end()

    tail = raw_entry[cursor:]
    if "$" in tail:
        raise PasskeyError(f"Invalid variable syntax in secret reference entry '{raw_entry}'")
    parts.append(tail)
    return "".join(parts)


def parse_reference(uri: str, env: Mapping[str, str] | None = None) -> tuple[str, str]:
    """Parse and validate a passkey://<entry>/<field> URI.

    Interpolation ($VAR / ${VAR}) is restricted strictly to <entry>; the
    resolved entry name is validated against ENTRY_NAME_PATTERN and
    RESERVED_NAMES so path traversal or field injection is impossible.
    """
    if not isinstance(uri, str):
        raise PasskeyError("Secret reference must be a string")

    trimmed = uri.strip()
    if not trimmed.startswith(REFERENCE_SCHEME):
        raise PasskeyError(f"Invalid secret reference URI (expected passkey://): '{uri}'")

    remainder = trimmed[len(REFERENCE_SCHEME) :]
    if not remainder or "?" in remainder or "#" in remainder or "\\" in remainder:
        raise PasskeyError(f"Malformed secret reference URI: '{uri}'")

    segments = remainder.split("/")
    if len(segments) != 2:
        raise PasskeyError(
            f"Secret reference must have exact format 'passkey://<entry>/<field>': '{uri}'"
        )

    raw_entry, field_name = segments
    if not raw_entry or not field_name:
        raise PasskeyError(f"Entry and field names cannot be empty in reference: '{uri}'")

    if "$" in field_name:
        raise PasskeyError(
            "Environment variable interpolation is only permitted in the entry segment "
            f"of passkey:// references: '{uri}'"
        )

    env_map = os.environ if env is None else env
    resolved_entry = _interpolate_entry_segment(raw_entry, env_map)

    if not is_valid_name(resolved_entry):
        raise PasskeyError(
            f"Invalid or disallowed entry name '{resolved_entry}' in secret reference"
        )

    if ".." in field_name or not _FIELD_NAME_PATTERN.match(field_name):
        raise PasskeyError(f"Invalid field name '{field_name}' in secret reference")

    return resolved_entry, field_name


def resolve_reference(
    uri: str,
    *,
    env: Mapping[str, str] | None = None,
    entry_cache: dict[str, Entry | None] | None = None,
    authorize_fn: Callable[[Entry], None] | None = None,
    log_read: bool = True,
) -> tuple[str, bool]:
    """Resolve passkey://<entry>/<field> -> (value, is_secret)."""
    entry_name, field_name = parse_reference(uri, env=env)

    if entry_cache is not None and entry_name in entry_cache:
        entry = entry_cache[entry_name]
    else:
        entry = get_entry(entry_name) if log_read else _get_entry(entry_name, log_read=False)
        if entry_cache is not None:
            entry_cache[entry_name] = entry

    if entry is None:
        raise PasskeyError(
            f"Referenced entry '{entry_name}' not found. "
            f"Ask the user to run 'passkey new {entry_name}' in their terminal "
            "(never paste secrets into chat)."
        )

    if authorize_fn is not None:
        authorize_fn(entry)

    if field_name in entry.fields:
        return entry.fields[field_name], True
    if field_name in entry.config:
        return entry.config[field_name], False

    raise PasskeyError(
        f"Field '{field_name}' not found in entry '{entry_name}'. "
        f"Ask the user to run 'passkey entry set-field {entry_name} {field_name}' in their terminal."
    )


def parse_dotenv_file(path: Path) -> dict[str, str]:
    """Parse a dotenv file into a dictionary without executing shell expansions."""
    expanded = path.expanduser()
    if not expanded.exists():
        raise PasskeyError(f"Environment file not found: '{expanded}'")
    if expanded.is_dir():
        raise PasskeyError(f"Environment file path is a directory: '{expanded}'")

    result: dict[str, str] = {}
    try:
        lines = expanded.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        raise PasskeyError(f"Failed to read env file '{expanded}': {e}") from e

    for line_no, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            raise PasskeyError(f"Invalid line {line_no} in '{expanded}': expected KEY=VALUE")
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            raise PasskeyError(f"Invalid variable name '{key}' on line {line_no} in '{expanded}'")
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        elif " #" in val:
            val = val.split(" #", 1)[0].rstrip()
        result[key] = val

    return result


def render_template(
    template_text: str,
    *,
    env: Mapping[str, str] | None = None,
    authorize_fn: Callable[[Entry], None] | None = None,
) -> str:
    """Resolve all {{ passkey://entry/field }} placeholders in template_text."""
    cache: dict[str, Entry | None] = {}

    def _replace(match: re.Match[str]) -> str:
        ref_uri = match.group(1)
        value, _ = resolve_reference(
            ref_uri,
            env=env,
            entry_cache=cache,
            authorize_fn=authorize_fn,
            log_read=True,
        )
        return value

    return _TEMPLATE_PLACEHOLDER_PATTERN.sub(_replace, template_text)


def extract_references_from_text(content: str) -> list[str]:
    """Find all passkey:// reference URIs in a template, dotenv, or config text."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _TEMPLATE_PLACEHOLDER_PATTERN.finditer(content):
        uri = match.group(1).strip()
        if uri not in seen:
            seen.add(uri)
            found.append(uri)
    for match in _BARE_REFERENCE_PATTERN.finditer(content):
        uri = match.group(0).strip().rstrip(",;")
        if uri not in seen:
            seen.add(uri)
            found.append(uri)
    return found


def validate_references_in_file(
    file_path: str | Path,
    *,
    env: Mapping[str, str] | None = None,
) -> dict:
    """Validate all passkey:// references in file_path without exposing any secret values."""
    path = Path(file_path).expanduser()
    if not path.exists() or not path.is_file():
        raise PasskeyError(f"Reference template file not found: '{path}'")

    from .leases import peek_all_leases

    active_leases = peek_all_leases()
    content = path.read_text(encoding="utf-8")
    uris = extract_references_from_text(content)
    cache: dict[str, Entry | None] = {}
    missing: list[dict[str, str]] = []
    prompt_without_lease: set[str] = set()

    for uri in uris:
        try:
            entry_name, field_name = parse_reference(uri, env=env)
        except PasskeyError as e:
            missing.append({"reference": uri, "reason": str(e)})
            continue

        if entry_name not in cache:
            cache[entry_name] = _get_entry(entry_name, log_read=False)
        entry = cache[entry_name]
        if entry is None:
            missing.append({"reference": uri, "reason": f"entry '{entry_name}' not found"})
        elif field_name not in entry.fields and field_name not in entry.config:
            missing.append(
                {
                    "reference": uri,
                    "reason": f"field '{field_name}' not found in entry '{entry_name}'",
                }
            )
        elif getattr(entry, "policy", "allow") == "prompt" and entry_name not in active_leases:
            prompt_without_lease.add(entry_name)

    return {
        "valid": len(missing) == 0,
        "checked": len(uris),
        "missing": missing,
        "prompt_entries_without_lease": sorted(prompt_without_lease),
        "will_prompt_biometric": bool(prompt_without_lease),
    }
