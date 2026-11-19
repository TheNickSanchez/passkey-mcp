"""Out-of-band native OS secure secret capture for headless AI agents."""

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

from .audit import detect_actor, log_operation
from .dirs import ensure_data_dir, get_data_dir
from .keychain import PasskeyError, _get_entry, save_entry
from .models import VALID_POLICIES, Entry, is_valid_name

_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")

MAX_REQUEST_FIELDS = 10
MAX_HINT_LENGTH = 200
MIN_TIMEOUT_SECONDS = 5
MAX_TIMEOUT_SECONDS = 300
DEFAULT_COOLDOWN_SECONDS = 2.0
CANCEL_COOLDOWN_SECONDS = 10.0

# Static AppleScript read from stdin via `osascript -`.
# Uses StandardAdditions `display dialog ... with hidden answer` and reads all
# dynamic strings via `system attribute` environment variables — zero `-e` argv
# interpolation, zero `System Events` TCC Automation prompts, zero injection surface.
_APPLESCRIPT_HIDDEN_DIALOG = """\
set dlgTitle to system attribute "PASSKEY_REQ_TITLE"
set dlgPrompt to system attribute "PASSKEY_REQ_PROMPT"
set dlgTimeout to (system attribute "PASSKEY_REQ_TIMEOUT") as integer
set res to display dialog dlgPrompt with title dlgTitle default answer "" buttons {"Cancel", "Save to Keychain"} default button "Save to Keychain" cancel button "Cancel" with hidden answer giving up after dlgTimeout
if gave up of res then
    error "PASSKEY_DIALOG_TIMEOUT" number -1712
end if
return text returned of res
"""


def _ratelimit_path():
    return get_data_dir() / ".request_ratelimit.json"


def _check_and_record_ratelimit(cooldown: float) -> None:
    """Enforce file-backed popup cooldown so runaway agents cannot spam OS dialogs."""
    if cooldown <= 0:
        return
    ensure_data_dir()
    path = _ratelimit_path()
    now = time.time()
    if path.exists():
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            blocked_until = float(state.get("blocked_until", 0.0))
            if now < blocked_until:
                wait_s = max(1, round(blocked_until - now, 1))
                raise PasskeyError(
                    f"Out-of-band secret prompt rate-limited ({wait_s}s remaining). "
                    "Wait before triggering another native dialog.",
                    error_code="RATE_LIMITED",
                )
        except PasskeyError:
            raise
        except (OSError, ValueError, json.JSONDecodeError):
            pass

    _write_ratelimit_until(now + cooldown)


def _write_ratelimit_until(blocked_until: float) -> None:
    ensure_data_dir()
    path = _ratelimit_path()
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".ratelimit-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps({"blocked_until": blocked_until}) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _parse_and_validate_fields(raw_fields: list[str] | str) -> list[str]:
    tokens: list[str] = []
    raw_items = [raw_fields] if isinstance(raw_fields, str) else list(raw_fields)
    for item in raw_items:
        for part in str(item).replace(",", " ").split():
            cleaned = part.strip()
            if cleaned:
                tokens.append(cleaned)

    deduped: list[str] = []
    seen: set[str] = set()
    for field_name in tokens:
        if not _FIELD_NAME_RE.match(field_name):
            raise PasskeyError(
                f"Invalid field name '{field_name}'. "
                "Field names must match ^[A-Za-z_][A-Za-z0-9_]{0,127}$.",
                error_code="INVALID_USAGE",
            )
        if field_name not in seen:
            seen.add(field_name)
            deduped.append(field_name)

    if not deduped:
        raise PasskeyError(
            "Specify at least one field name via --fields.",
            error_code="INVALID_USAGE",
        )
    if len(deduped) > MAX_REQUEST_FIELDS:
        raise PasskeyError(
            f"Cannot request more than {MAX_REQUEST_FIELDS} fields in one call "
            f"(got {len(deduped)}).",
            error_code="INVALID_USAGE",
        )
    return deduped


_UNICODE_ASCII_TRANSLATION = str.maketrans(
    {
        "\u2014": "-",   # em dash
        "\u2013": "-",   # en dash
        "\u2192": "->",  # right arrow
        "\u2190": "<-",  # left arrow
        "\u2026": "...", # ellipsis
        "\u2018": "'",   # left single quote
        "\u2019": "'",   # right single quote
        "\u201c": '"',   # left double quote
        "\u201d": '"',   # right double quote
        "\u2022": "*",   # bullet
        "\u00a0": " ",   # non-breaking space
    }
)


def _to_applescript_attr_ascii(text: str) -> str:
    """Normalize text to 7-bit ASCII for AppleScript `system attribute`.

    macOS StandardAdditions `system attribute` decodes environment variables
    using legacy MacRoman rather than UTF-8 (which turns UTF-8 '—' into ',Äî').
    Restricting dialog title/prompt attributes to 7-bit ASCII keeps UTF-8 and
    MacRoman byte-for-byte identical.
    """
    translated = text.translate(_UNICODE_ASCII_TRANSLATION)
    return translated.encode("ascii", "replace").decode("ascii")


def _sanitize_hint(hint: str | None) -> str:
    if not hint:
        return ""
    cleaned = _CONTROL_CHARS_RE.sub(" ", str(hint)).strip()
    if len(cleaned) > MAX_HINT_LENGTH:
        cleaned = cleaned[:MAX_HINT_LENGTH].rstrip() + "..."
    return cleaned


def _strip_single_trailing_newline(raw: str) -> str:
    if raw.endswith("\r\n"):
        return raw[:-2]
    if raw.endswith("\n"):
        return raw[:-1]
    return raw


def _prompt_macos_hidden_dialog(
    *,
    entry_name: str,
    field_name: str,
    field_index: int,
    field_total: int,
    client_label: str,
    hint: str,
    timeout: int,
    remaining_fields: list[str],
) -> str:
    """Capture a single secret value via macOS StandardAdditions hidden dialog."""
    step_str = f" ({field_index}/{field_total})" if field_total > 1 else ""
    title = _to_applescript_attr_ascii(f"Passkey - Secret Request{step_str}")
    prompt_lines = [
        f"Enter '{field_name}' for keychain entry '{entry_name}'.",
        f"Requested by: {client_label} (saved directly to OS Keychain; never shown to AI).",
    ]
    if hint:
        prompt_lines.append(f"Hint: {hint}")
    prompt_text = _to_applescript_attr_ascii("\n\n".join(prompt_lines))

    env = os.environ.copy()
    env["PASSKEY_REQ_TITLE"] = title
    env["PASSKEY_REQ_PROMPT"] = prompt_text
    env["PASSKEY_REQ_TIMEOUT"] = str(int(timeout))

    try:
        proc = subprocess.run(
            ["osascript", "-"],
            input=_APPLESCRIPT_HIDDEN_DIALOG,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except FileNotFoundError as e:
        raise PasskeyError(
            "macOS 'osascript' binary not found.",
            error_code="GUI_UNAVAILABLE",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        ) from e
    except subprocess.TimeoutExpired as e:
        raise PasskeyError(
            f"Secret input dialog timed out after {timeout}s while waiting for '{field_name}'.",
            error_code="REQUEST_TIMEOUT",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        ) from e
    except OSError as e:
        raise PasskeyError(
            f"Native OS dialog unavailable in this environment ({e}). "
            f"Call MCP 'passkey_request_secret' or ask the user to run 'passkey new {entry_name}'.",
            error_code="GUI_UNAVAILABLE",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        ) from e

    if proc.returncode != 0:
        err_text = (proc.stderr or "").strip()
        if "PASSKEY_DIALOG_TIMEOUT" in err_text or "-1712" in err_text:
            raise PasskeyError(
                f"Secret input dialog timed out after {timeout}s while waiting for '{field_name}'.",
                error_code="REQUEST_TIMEOUT",
                entry=entry_name,
                missing_fields=remaining_fields,
                remediation_command=f"passkey new {entry_name}",
            )
        if "-128" in err_text or "User canceled" in err_text or "canceled" in err_text.lower():
            raise PasskeyError(
                f"User cancelled secret dialog for '{entry_name}' ('{field_name}').",
                error_code="REQUEST_CANCELLED",
                entry=entry_name,
                missing_fields=remaining_fields,
                remediation_command=f"passkey new {entry_name}",
            )
        raise PasskeyError(
            f"Native OS dialog could not open ({err_text or 'GUI unavailable'}). "
            "If running inside a sandboxed CLI subprocess, use the MCP tool "
            f"'passkey_request_secret' or ask the user to run 'passkey new {entry_name}'.",
            error_code="GUI_UNAVAILABLE",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        )

    secret_value = _strip_single_trailing_newline(proc.stdout)
    if not secret_value.strip():
        raise PasskeyError(
            f"Empty secret value entered for '{field_name}' in '{entry_name}'.",
            error_code="EMPTY_SECRET_REJECTED",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey entry set-field {entry_name} {field_name}",
        )
    return secret_value


def _prompt_linux_zenity(
    *,
    entry_name: str,
    field_name: str,
    field_index: int,
    field_total: int,
    hint: str,
    timeout: int,
    remaining_fields: list[str],
) -> str:
    """Capture a single secret value via Linux zenity --password dialog."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise PasskeyError(
            f"No GUI display available for out-of-band prompt. Ask the user to run "
            f"'passkey new {entry_name}' in their terminal.",
            error_code="GUI_UNAVAILABLE",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        )
    zenity_bin = shutil.which("zenity")
    if not zenity_bin:
        raise PasskeyError(
            f"'zenity' is not installed for GUI secret capture. Ask the user to run "
            f"'passkey new {entry_name}' in their terminal.",
            error_code="GUI_UNAVAILABLE",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        )

    step_str = f" ({field_index}/{field_total})" if field_total > 1 else ""
    title = f"Passkey: {entry_name}/{field_name}{step_str}"
    if hint:
        title = f"{title} — {hint[:60]}"

    try:
        proc = subprocess.run(
            [zenity_bin, "--password", f"--title={title}", f"--timeout={int(timeout)}"],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired as e:
        raise PasskeyError(
            f"Secret input dialog timed out after {timeout}s while waiting for '{field_name}'.",
            error_code="REQUEST_TIMEOUT",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        ) from e
    except OSError as e:
        raise PasskeyError(
            f"Failed to launch zenity dialog: {e}",
            error_code="GUI_UNAVAILABLE",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        ) from e

    if proc.returncode == 5:
        raise PasskeyError(
            f"Secret input dialog timed out after {timeout}s while waiting for '{field_name}'.",
            error_code="REQUEST_TIMEOUT",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        )
    if proc.returncode != 0:
        raise PasskeyError(
            f"User cancelled secret dialog for '{entry_name}' ('{field_name}').",
            error_code="REQUEST_CANCELLED",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey new {entry_name}",
        )

    secret_value = _strip_single_trailing_newline(proc.stdout)
    if not secret_value.strip():
        raise PasskeyError(
            f"Empty secret value entered for '{field_name}' in '{entry_name}'.",
            error_code="EMPTY_SECRET_REJECTED",
            entry=entry_name,
            missing_fields=remaining_fields,
            remediation_command=f"passkey entry set-field {entry_name} {field_name}",
        )
    return secret_value


def _prompt_native_secret_field(
    *,
    entry_name: str,
    field_name: str,
    field_index: int,
    field_total: int,
    client_label: str,
    hint: str,
    timeout: int,
    remaining_fields: list[str],
) -> str:
    if sys.platform == "darwin":
        return _prompt_macos_hidden_dialog(
            entry_name=entry_name,
            field_name=field_name,
            field_index=field_index,
            field_total=field_total,
            client_label=client_label,
            hint=hint,
            timeout=timeout,
            remaining_fields=remaining_fields,
        )
    if sys.platform.startswith("linux"):
        return _prompt_linux_zenity(
            entry_name=entry_name,
            field_name=field_name,
            field_index=field_index,
            field_total=field_total,
            hint=hint,
            timeout=timeout,
            remaining_fields=remaining_fields,
        )
    raise PasskeyError(
        f"Out-of-band native secret dialogs are not supported on platform '{sys.platform}'. "
        f"Ask the user to run 'passkey new {entry_name}' in their terminal.",
        error_code="GUI_UNAVAILABLE",
        entry=entry_name,
        missing_fields=remaining_fields,
        remediation_command=f"passkey new {entry_name}",
    )


def request_secret(
    entry_name: str,
    fields: list[str] | str,
    *,
    policy: str | None = None,
    hint: str | None = None,
    timeout: int = 120,
    overwrite: bool = False,
    cooldown_seconds: float | None = None,
) -> dict:
    """Prompt the human user via native OS hidden input and store directly in keychain.

    Never echoes, logs, or returns secret values. Preserves all existing Entry
    metadata (config, created, source, last_rotated, and unrequested fields).
    """
    if not is_valid_name(entry_name):
        raise PasskeyError(
            f"Invalid entry name '{entry_name}'.",
            error_code="INVALID_USAGE",
        )

    parsed_fields = _parse_and_validate_fields(fields)

    normalized_policy: str | None = None
    if policy is not None:
        normalized_policy = policy.strip().lower()
        if normalized_policy not in VALID_POLICIES:
            raise PasskeyError(
                f"Invalid policy '{policy}'. Expected one of: {', '.join(sorted(VALID_POLICIES))}",
                error_code="INVALID_USAGE",
            )

    if isinstance(timeout, bool) or not isinstance(timeout, int) or not (
        MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS
    ):
        raise PasskeyError(
            f"Timeout must be between {MIN_TIMEOUT_SECONDS}s and {MAX_TIMEOUT_SECONDS}s "
            f"(got {timeout!r}).",
            error_code="INVALID_USAGE",
        )

    safe_hint = _sanitize_hint(hint)
    existing = _get_entry(entry_name, log_read=False)

    if existing is not None and not overwrite:
        fields_to_prompt = [
            f for f in parsed_fields if f not in existing.fields or not existing.fields[f]
        ]
    else:
        fields_to_prompt = list(parsed_fields)

    if not fields_to_prompt:
        assert existing is not None
        if normalized_policy is not None and existing.policy != normalized_policy:
            existing.policy = normalized_policy
            save_entry(existing, is_update=True)
        return {
            "ok": True,
            "status": "already_exists",
            "entry": entry_name,
            "fields_saved": [],
            "fields_present": sorted(existing.fields.keys()),
            "policy": existing.policy,
        }

    eff_cooldown = (
        DEFAULT_COOLDOWN_SECONDS if cooldown_seconds is None else float(cooldown_seconds)
    )
    _check_and_record_ratelimit(eff_cooldown)

    client_label = str(detect_actor().get("client") or "agent")
    captured: dict[str, str] = {}
    total = len(fields_to_prompt)

    try:
        for idx, fld in enumerate(fields_to_prompt, start=1):
            remaining = fields_to_prompt[idx - 1 :]
            val = _prompt_native_secret_field(
                entry_name=entry_name,
                field_name=fld,
                field_index=idx,
                field_total=total,
                client_label=client_label,
                hint=safe_hint,
                timeout=timeout,
                remaining_fields=remaining,
            )
            captured[fld] = val
    except PasskeyError as err:
        if err.error_code == "REQUEST_CANCELLED" and eff_cooldown > 0:
            _write_ratelimit_until(time.time() + max(eff_cooldown, CANCEL_COOLDOWN_SECONDS))
        log_operation("request_secret", entry_name, success=False)
        raise

    if existing is not None:
        merged_fields = existing.fields.copy()
        merged_fields.update(captured)
        final_policy = normalized_policy if normalized_policy is not None else existing.policy
        entry_obj = Entry(
            name=entry_name,
            fields=merged_fields,
            config=existing.config.copy(),
            created=existing.created,
            source=existing.source,
            last_rotated=existing.last_rotated,
            policy=final_policy,
        )
        save_entry(entry_obj, is_update=True)
        status = "updated"
    else:
        final_policy = normalized_policy if normalized_policy is not None else "allow"
        entry_obj = Entry(
            name=entry_name,
            fields=captured,
            source=f"request:{client_label}",
            policy=final_policy,
        )
        save_entry(entry_obj, is_update=False)
        status = "created"

    saved_names = list(captured.keys())
    log_operation(
        "request_secret",
        entry_name,
        details={
            "field_count": len(saved_names),
            "policy": final_policy,
            "updated": existing is not None,
        },
    )

    return {
        "ok": True,
        "status": status,
        "entry": entry_name,
        "fields_saved": saved_names,
        "fields_present": sorted(entry_obj.fields.keys()),
        "policy": entry_obj.policy,
    }


def cmd_request(
    entry_name: str,
    fields: list[str],
    *,
    policy: str | None = None,
    hint: str | None = None,
    timeout: int = 120,
    overwrite: bool = False,
    json_output: bool = False,
) -> None:
    """CLI wrapper for ``passkey request``."""
    res = request_secret(
        entry_name,
        fields,
        policy=policy,
        hint=hint,
        timeout=timeout,
        overwrite=overwrite,
    )
    if json_output:
        print(json.dumps(res, indent=2))
        return

    if res["status"] == "already_exists":
        print(
            f"Entry '{entry_name}' already contains requested field(s) "
            f"({', '.join(res['fields_present'])}; policy={res['policy']})."
        )
    else:
        verb = "Created" if res["status"] == "created" else "Updated"
        print(
            f"{verb} '{entry_name}' via secure OS prompt "
            f"(saved: {', '.join(res['fields_saved'])}; policy={res['policy']})."
        )
