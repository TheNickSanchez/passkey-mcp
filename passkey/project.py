"""Project manifest discovery, HMAC-signed repo trust store, and zero-config exec."""

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import keyring
from keyring.errors import KeyringError

from .audit import detect_actor, log_operation
from .dirs import ensure_data_dir, get_data_dir
from .find import find_env_vars
from .hooks import is_sensitive_secret_path
from .interactive import can_prompt_interactively
from .keychain import KeychainAccessError, PasskeyError
from .models import is_valid_name
from .references import parse_dotenv_file
from .runner import preflight_run, run_with_secrets

try:
    import tomllib as _tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    _tomllib = None

TRUST_HMAC_SERVICE = "passkey"
TRUST_HMAC_KEY_NAME = "__trust_hmac_key__"

_AUTO_TEMPLATE_CANDIDATES: tuple[str, ...] = (
    ".env.example",
    ".env.template",
    ".env.sample",
    ".env.schema",
    ".env.dist",
)


def get_trusted_projects_path() -> Path:
    """Return path to <data_dir>/trusted_projects.json."""
    return get_data_dir() / "trusted_projects.json"


def _fallback_trust_key_path() -> Path:
    return ensure_data_dir() / ".trust_hmac_key"


def _get_or_create_trust_hmac_key() -> bytes:
    """Load or generate 32-byte trust HMAC key in OS keyring (with 0o600 file fallback)."""
    try:
        stored = keyring.get_password(TRUST_HMAC_SERVICE, TRUST_HMAC_KEY_NAME)
        if stored and len(stored) >= 64:
            return bytes.fromhex(stored.strip())
        new_hex = secrets.token_hex(32)
        keyring.set_password(TRUST_HMAC_SERVICE, TRUST_HMAC_KEY_NAME, new_hex)
        return bytes.fromhex(new_hex)
    except (KeyringError, ValueError) as e:
        key_file = _fallback_trust_key_path()
        if key_file.exists():
            try:
                return bytes.fromhex(key_file.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                pass
        if isinstance(e, KeyringError) and get_trusted_projects_path().exists():
            raise KeychainAccessError(
                f"Failed to access Keychain to verify trusted_projects.json: {e}"
            ) from e
        new_hex = secrets.token_hex(32)
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(new_hex + "\n")
        return bytes.fromhex(new_hex)


def _compute_trust_hmac(key: bytes, projects_map: dict) -> str:
    canonical = json.dumps(projects_map, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _load_trust_store(*, create_key: bool = True) -> tuple[dict[str, dict], bytes | None]:
    """Load and verify HMAC of trusted_projects.json."""
    path = get_trusted_projects_path()
    if not path.exists():
        key = _get_or_create_trust_hmac_key() if create_key else None
        return {}, key

    key = _get_or_create_trust_hmac_key()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise PasskeyError(
            f"Trusted projects store is corrupted or unreadable: {e}",
            error_code="TRUST_STORE_TAMPERED",
            remediation_command="passkey project trust",
        ) from e

    if not isinstance(raw, dict):
        raise PasskeyError(
            "Trusted projects integrity check failed: invalid structure.",
            error_code="TRUST_STORE_TAMPERED",
            remediation_command="passkey project trust",
        )

    projects_map = raw.get("projects")
    stored_hmac = raw.get("hmac")
    if not isinstance(projects_map, dict) or not isinstance(stored_hmac, str):
        raise PasskeyError(
            "Trusted projects integrity check failed: missing projects payload or HMAC signature.",
            error_code="TRUST_STORE_TAMPERED",
            remediation_command="passkey project trust",
        )

    expected_hmac = _compute_trust_hmac(key, projects_map)
    if not hmac.compare_digest(stored_hmac, expected_hmac):
        raise PasskeyError(
            "Trusted projects integrity check failed: trusted_projects.json HMAC mismatch "
            "(tampering detected).",
            error_code="TRUST_STORE_TAMPERED",
            remediation_command="passkey project trust",
        )

    return dict(projects_map), key


def _save_trust_store(projects_map: dict[str, dict], key: bytes) -> None:
    """Atomically write HMAC-signed trusted_projects.json with 0o600 permissions."""
    ensure_data_dir()
    path = get_trusted_projects_path()
    payload = {
        "version": 1,
        "projects": projects_map,
        "hmac": _compute_trust_hmac(key, projects_map),
    }
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".trust-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, indent=2) + "\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _parse_str_list_literal(raw_val: str) -> list[str]:
    """Minimal TOML string-array parser for Python 3.10 fallback."""
    val = raw_val.strip()
    if not (val.startswith("[") and val.endswith("]")):
        raise PasskeyError(f"Expected TOML list literal, got: {raw_val}", error_code="INVALID_MANIFEST")
    inner = val[1:-1].strip()
    if not inner:
        return []
    items: list[str] = []
    for part in inner.split(","):
        cleaned = part.strip()
        if not cleaned:
            continue
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in ('"', "'"):
            items.append(cleaned[1:-1])
        else:
            raise PasskeyError(
                f"Invalid string element in .passkey.toml array: {part}",
                error_code="INVALID_MANIFEST",
            )
    return items


def parse_passkey_toml(toml_path: Path) -> dict:
    """Parse [project] and [plugins] sections from .passkey.toml."""
    content = toml_path.read_text(encoding="utf-8")
    if _tomllib is not None:
        try:
            parsed = _tomllib.loads(content)
        except Exception as e:
            raise PasskeyError(
                f"Invalid TOML in '{toml_path}': {e}",
                error_code="INVALID_MANIFEST",
            ) from e
        project_sec = parsed.get("project", {})
        plugins_sec = parsed.get("plugins", {})
        if not isinstance(project_sec, dict) or not isinstance(plugins_sec, dict):
            raise PasskeyError(
                f"Invalid section types in '{toml_path}'.",
                error_code="INVALID_MANIFEST",
            )
        return {
            "project": {
                "entries": [str(x) for x in project_sec.get("entries", []) if isinstance(x, str)],
                "env_files": [str(x) for x in project_sec.get("env_files", []) if isinstance(x, str)],
                "required": [str(x) for x in project_sec.get("required", []) if isinstance(x, str)],
            },
            "plugins": {
                str(k): str(v)
                for k, v in plugins_sec.items()
                if isinstance(k, str) and isinstance(v, str)
            },
        }

    # Python 3.10 fallback parser
    section = ""
    project_data: dict[str, list[str]] = {"entries": [], "env_files": [], "required": []}
    plugins_data: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        key = k.strip().strip("'\"")
        val = v.strip()
        if " #" in val:
            val = val.split(" #", 1)[0].strip()
        if section == "project" and key in project_data:
            project_data[key] = _parse_str_list_literal(val)
        elif section == "plugins":
            plugins_data[key] = val.strip("'\"")
    return {"project": project_data, "plugins": plugins_data}


def write_passkey_toml(
    project_dir: Path,
    *,
    project_section: dict | None = None,
    plugins_section: dict[str, str] | None = None,
) -> Path:
    """Atomically write .passkey.toml preserving existing [project] and [plugins] sections."""
    toml_path = project_dir / ".passkey.toml"
    existing = (
        parse_passkey_toml(toml_path)
        if toml_path.exists()
        else {"project": {"entries": [], "env_files": [], "required": []}, "plugins": {}}
    )

    proj = dict(existing["project"])
    if project_section is not None:
        for k in ("entries", "env_files", "required"):
            if k in project_section and project_section[k] is not None:
                proj[k] = list(project_section[k])

    plugs = dict(existing["plugins"])
    if plugins_section is not None:
        plugs.update(plugins_section)

    lines: list[str] = [
        "# Committable passkey project manifest (contains entry/field references only, never secrets)"
    ]
    has_proj = any(proj.get(k) for k in ("entries", "env_files", "required"))
    if has_proj:
        lines.append("[project]")
        for k in ("entries", "env_files", "required"):
            vals = proj.get(k) or []
            if vals:
                rendered_list = ", ".join(json.dumps(str(x)) for x in vals)
                lines.append(f"{k} = [{rendered_list}]")
        if plugs:
            lines.append("")

    if plugs:
        lines.append("[plugins]")
        for k in sorted(plugs):
            key_fmt = f'"{k}"' if "-" in k else k
            lines.append(f'{key_fmt} = {json.dumps(plugs[k])}')

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


def _find_git_root(start_dir: Path) -> Path | None:
    """Return enclosing git repository root if start_dir is inside a git repo."""
    curr = start_dir.expanduser().resolve()
    home = Path.home().resolve()
    while True:
        if (curr / ".git").exists():
            return curr
        if curr == home or curr.parent == curr:
            return None
        curr = curr.parent


def _resolve_safe_project_env_file(project_root: Path, rel_or_path: str) -> Path:
    """Validate that a manifest env_file stays within project_root and is not a live .env."""
    if is_sensitive_secret_path(rel_or_path):
        raise PasskeyError(
            f"Manifest in '{project_root}' references disallowed sensitive file '{rel_or_path}'. "
            "Use '.env.passkey' with passkey:// URIs instead of plaintext .env files.",
            error_code="INVALID_MANIFEST",
        )
    candidate = (project_root / rel_or_path).resolve()
    try:
        candidate.relative_to(project_root)
    except ValueError:
        raise PasskeyError(
            f"Manifest env_file '{rel_or_path}' escapes project root '{project_root}'.",
            error_code="INVALID_MANIFEST",
        ) from None
    return candidate


def _compute_manifest_bundle_sha256(project_root: Path, extra_env_files: list[Path]) -> str:
    """Compute canonical SHA-256 over .passkey.toml, .env.passkey, and extra env_files.

    Includes explicit 'absent' markers for .passkey.toml and .env.passkey so
    dropping a new manifest file alongside an existing trusted file always
    invalidates the previous digest.
    """
    tracked: list[Path] = [
        project_root / ".passkey.toml",
        project_root / ".env.passkey",
    ]
    seen_paths = {p.resolve() for p in tracked}
    for ef in sorted(extra_env_files, key=lambda p: str(p)):
        rp = ef.resolve()
        if rp not in seen_paths:
            seen_paths.add(rp)
            tracked.append(rp)

    records: list[dict[str, str]] = []
    for p in tracked:
        try:
            rel = str(p.resolve().relative_to(project_root))
        except ValueError:
            rel = p.name
        if p.is_symlink():
            raise PasskeyError(
                f"Refusing symlinked project manifest file: '{p}'",
                error_code="INVALID_MANIFEST",
            )
        if p.is_file():
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            records.append({"file": rel, "state": "present", "sha256": digest})
        else:
            records.append({"file": rel, "state": "absent", "sha256": ""})

    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def discover_project_manifest(start_dir: str | Path | None = None) -> dict | None:
    """Discover .passkey.toml and/or .env.passkey up to the enclosing git root."""
    base = (Path(start_dir) if start_dir is not None else Path.cwd()).expanduser().resolve()
    if base.is_file():
        base = base.parent

    git_root = _find_git_root(base)
    stop_dir = git_root if git_root is not None else base

    curr = base
    manifest_root: Path | None = None
    while True:
        has_toml = (curr / ".passkey.toml").is_file() or (curr / ".passkey.toml").is_symlink()
        has_env_pk = (curr / ".env.passkey").is_file() or (curr / ".env.passkey").is_symlink()
        if has_toml or has_env_pk:
            manifest_root = curr
            break
        if curr == stop_dir or curr.parent == curr:
            break
        curr = curr.parent

    if manifest_root is None:
        return None

    toml_path = manifest_root / ".passkey.toml"
    env_pk_path = manifest_root / ".env.passkey"
    if toml_path.is_symlink() or env_pk_path.is_symlink():
        raise PasskeyError(
            f"Refusing symlinked project manifest in '{manifest_root}'.",
            error_code="INVALID_MANIFEST",
        )

    entries: list[str] = []
    required_vars: list[str] = []
    env_file_paths: list[Path] = []
    manifests_found: list[str] = []

    if toml_path.is_file():
        manifests_found.append(".passkey.toml")
        parsed_toml = parse_passkey_toml(toml_path)
        proj = parsed_toml["project"]
        for ent_name in proj.get("entries", []):
            if not is_valid_name(ent_name):
                raise PasskeyError(
                    f"Invalid entry name '{ent_name}' in '{toml_path}'.",
                    error_code="INVALID_MANIFEST",
                )
            if ent_name not in entries:
                entries.append(ent_name)
        for ef_str in proj.get("env_files", []):
            resolved_ef = _resolve_safe_project_env_file(manifest_root, ef_str)
            if resolved_ef not in env_file_paths:
                env_file_paths.append(resolved_ef)
        for req_var in proj.get("required", []):
            if req_var not in required_vars:
                required_vars.append(req_var)

    if env_pk_path.is_file():
        manifests_found.append(".env.passkey")
        resolved_default_ef = env_pk_path.resolve()
        if resolved_default_ef not in env_file_paths:
            env_file_paths.append(resolved_default_ef)

    manifest_sha256 = _compute_manifest_bundle_sha256(manifest_root, env_file_paths)

    return {
        "project_root": str(manifest_root),
        "manifests": manifests_found,
        "entries": entries,
        "env_files": [str(p) for p in env_file_paths],
        "required_vars": required_vars,
        "manifest_sha256": manifest_sha256,
    }


def check_project_trust(manifest: dict) -> dict:
    """Read-only check verifying whether manifest['manifest_sha256'] is HMAC-trusted."""
    projects_map, _ = _load_trust_store(create_key=False)
    root_key = manifest["project_root"]
    rec = projects_map.get(root_key)
    if not isinstance(rec, dict):
        return {
            "trusted": False,
            "trust_status": "untrusted",
            "trusted_at": None,
        }
    if rec.get("manifest_sha256") != manifest["manifest_sha256"]:
        return {
            "trusted": False,
            "trust_status": "manifest_modified",
            "trusted_at": rec.get("trusted_at"),
        }
    return {
        "trusted": True,
        "trust_status": "trusted",
        "trusted_at": rec.get("trusted_at"),
    }


def _record_project_trust(manifest: dict) -> dict:
    """Persist HMAC-signed trust record for manifest."""
    projects_map, key = _load_trust_store(create_key=True)
    assert key is not None
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    root_key = manifest["project_root"]
    record = {
        "project_root": root_key,
        "manifest_sha256": manifest["manifest_sha256"],
        "manifests": list(manifest["manifests"]),
        "trusted_at": now_iso,
        "trusted_by": detect_actor().get("client", "terminal"),
    }
    projects_map[root_key] = record
    _save_trust_store(projects_map, key)
    log_operation(
        "project_trust",
        details={"manifests": manifest["manifests"], "trust_status": "trusted"},
    )
    return record


def trust_project(
    project_dir: str | Path | None = None,
    *,
    revoke: bool = False,
) -> dict:
    """Explicitly trust or revoke trust for a project directory's manifest."""
    base = (Path(project_dir) if project_dir is not None else Path.cwd()).expanduser().resolve()
    if revoke:
        projects_map, key = _load_trust_store(create_key=True)
        assert key is not None
        git_root = _find_git_root(base)
        removed = False
        for candidate in {str(base), str(git_root) if git_root else str(base)}:
            if candidate in projects_map:
                del projects_map[candidate]
                removed = True
        if removed:
            _save_trust_store(projects_map, key)
        log_operation("project_trust_revoke", details={"updated": removed})
        return {"ok": True, "project_root": str(base), "trusted": False, "revoked": removed}

    manifest = discover_project_manifest(base)
    if manifest is None:
        raise PasskeyError(
            f"No .env.passkey or .passkey.toml manifest found in '{base}'. "
            "Run 'passkey project init' first.",
            error_code="PROJECT_MANIFEST_NOT_FOUND",
            remediation_command="passkey project init",
        )

    # Prevent headless AI agents from silently self-approving untrusted manifests without OS auth
    if not can_prompt_interactively():
        from .auth import authenticate

        root_name = Path(manifest["project_root"]).name
        if not authenticate(f"Passkey: trust project manifest in '{root_name}'"):
            log_operation("project_trust_denied", success=False)
            raise PasskeyError(
                f"Biometric/OS approval required to trust manifest in '{manifest['project_root']}'. "
                f"Ask the user to run 'passkey project trust --project-dir {manifest['project_root']}' "
                "in their terminal.",
                error_code="UNTRUSTED_PROJECT",
                remediation_command=f"passkey project trust --project-dir {manifest['project_root']}",
            )

    rec = _record_project_trust(manifest)
    return {
        "ok": True,
        "project_root": rec["project_root"],
        "trusted": True,
        "trust_status": "trusted",
        "manifest_sha256": rec["manifest_sha256"],
        "manifests": rec["manifests"],
    }


def ensure_project_trusted(manifest: dict) -> None:
    """Enforce HMAC manifest trust before injecting secrets in ``passkey exec``."""
    trust = check_project_trust(manifest)
    if trust["trusted"]:
        return

    from .auth import authenticate

    root_path = Path(manifest["project_root"])
    summary_parts: list[str] = []
    if manifest["entries"]:
        summary_parts.append(f"entries: {', '.join(manifest['entries'][:4])}")
    if manifest["manifests"]:
        summary_parts.append(", ".join(manifest["manifests"]))
    summary = "; ".join(summary_parts) or "project secrets"
    reason_prefix = (
        "re-approve modified manifest"
        if trust["trust_status"] == "manifest_modified"
        else "trust project manifest"
    )
    approved = authenticate(f"Passkey: {reason_prefix} in '{root_path.name}' ({summary})")
    if not approved:
        log_operation(
            "project_exec_blocked",
            details={"trust_status": trust["trust_status"], "manifests": manifest["manifests"]},
            success=False,
        )
        raise PasskeyError(
            f"Refusing to auto-inject secrets from {trust['trust_status']} manifest in "
            f"'{manifest['project_root']}'. Ask the user to approve Touch ID or run "
            f"'passkey project trust --project-dir {manifest['project_root']}'.",
            error_code="UNTRUSTED_PROJECT",
            remediation_command=f"passkey project trust --project-dir {manifest['project_root']}",
        )

    _record_project_trust(manifest)


def get_project_status(
    project_dir: str | Path | None = None,
    *,
    command: list[str] | None = None,
) -> dict:
    """Return complete manifest discovery, trust verification, and preflight readiness."""
    base = (Path(project_dir) if project_dir is not None else Path.cwd()).expanduser().resolve()
    manifest = discover_project_manifest(base)
    if manifest is None:
        candidates = [c for c in _AUTO_TEMPLATE_CANDIDATES if (base / c).is_file()]
        remediation_cmd = (
            f"passkey project init --from-file {candidates[0]}"
            if candidates
            else "passkey project init"
        )
        return {
            "ok": True,
            "manifest_found": False,
            "project_root": str(_find_git_root(base) or base),
            "manifests": [],
            "trusted": False,
            "trust_status": "no_manifest",
            "ready": False,
            "detected_templates": candidates,
            "remediation": [
                f"No .env.passkey or .passkey.toml found. Bootstrap with '{remediation_cmd}'."
            ],
            "remediation_command": remediation_cmd,
        }

    trust = check_project_trust(manifest)
    preflight = preflight_run(
        manifest["entries"],
        command=command,
        env_files=manifest["env_files"],
    )

    injected_set = set(preflight["injected_env_vars"])
    missing_required = [v for v in manifest["required_vars"] if v not in injected_set]
    remediation = list(preflight["remediation"])
    if missing_required:
        remediation.append(
            f"Missing required project variable(s): {', '.join(missing_required)}"
        )
    if not trust["trusted"]:
        remediation.append(
            f"Project manifest is {trust['trust_status']}; first 'passkey exec' will prompt "
            f"Touch ID, or run 'passkey project trust --project-dir {manifest['project_root']}'."
        )

    has_secret_sources = bool(manifest["entries"] or preflight["references_checked"] > 0)
    ready = (
        has_secret_sources
        and preflight["ready"]
        and not missing_required
    )

    return {
        "ok": True,
        "manifest_found": True,
        "project_root": manifest["project_root"],
        "manifests": manifest["manifests"],
        "manifest_sha256": manifest["manifest_sha256"],
        "trusted": trust["trusted"],
        "trust_status": trust["trust_status"],
        "ready": ready,
        "entries": manifest["entries"],
        "env_files": manifest["env_files"],
        "required_vars": manifest["required_vars"],
        "missing_required_vars": missing_required,
        "injected_env_vars": preflight["injected_env_vars"],
        "entries_missing": preflight["entries_missing"],
        "references_checked": preflight["references_checked"],
        "references_valid": preflight["references_valid"],
        "references_invalid": preflight["references_invalid"],
        "prompt_entries_without_lease": preflight["prompt_entries_without_lease"],
        "will_prompt_biometric": preflight["will_prompt_biometric"] or (not trust["trusted"]),
        "command": preflight["command"],
        "command_executable_found": preflight["command_executable_found"],
        "remediation": list(dict.fromkeys(remediation)),
    }


def init_project(
    *,
    project_dir: str | Path | None = None,
    from_file: str | Path | None = None,
    entries: list[str] | None = None,
    force: bool = False,
    no_trust: bool = False,
) -> dict:
    """Scan a safe template (.env.example) and generate .env.passkey / .passkey.toml."""
    root = (Path(project_dir) if project_dir is not None else Path.cwd()).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    chosen_template: Path | None = None
    if from_file is not None:
        if is_sensitive_secret_path(str(from_file)):
            raise PasskeyError(
                f"Refusing to read sensitive secret file '{from_file}'. "
                "Use '.env.example' or '.env.template' instead.",
                error_code="SENSITIVE_FILE_REFUSED",
                remediation_command="passkey project init --from-file .env.example",
            )
        chosen_template = Path(from_file).expanduser()
        if not chosen_template.is_absolute():
            chosen_template = (root / chosen_template).resolve()
        if not chosen_template.is_file():
            raise PasskeyError(
                f"Template file not found: '{chosen_template}'",
                error_code="FILE_NOT_FOUND",
            )
    else:
        for cand in _AUTO_TEMPLATE_CANDIDATES:
            cand_path = root / cand
            if cand_path.is_file() and not cand_path.is_symlink():
                chosen_template = cand_path
                break

    if chosen_template is None and not entries:
        raise PasskeyError(
            f"No template file ({', '.join(_AUTO_TEMPLATE_CANDIDATES)}) found in '{root}', "
            "and no --entries were specified.",
            error_code="PROJECT_MANIFEST_NOT_FOUND",
            remediation_command="passkey project init --entries <entry>",
        )

    for ent_name in entries or []:
        if not is_valid_name(ent_name):
            raise PasskeyError(
                f"Invalid entry name '{ent_name}'.",
                error_code="INVALID_USAGE",
            )

    written_files: list[str] = []
    mapped_vars: dict[str, str] = {}
    ambiguous_vars: dict[str, list[str]] = {}
    missing_vars: list[str] = []

    if chosen_template is not None:
        env_passkey_path = root / ".env.passkey"
        if env_passkey_path.exists() and not force:
            raise PasskeyError(
                f"'{env_passkey_path}' already exists. Pass --force to regenerate.",
                error_code="FILE_EXISTS",
                remediation_command="passkey project init --force",
            )

        parsed_tpl = parse_dotenv_file(chosen_template)
        tpl_vars = list(parsed_tpl.keys())
        lookup = find_env_vars(tpl_vars) if tpl_vars else {"matches": {}}

        lines = [
            f"# Generated by passkey project init from {chosen_template.name}",
            "# Safe to commit: contains passkey:// pointers only, never secret values.",
        ]
        for var in tpl_vars:
            raw_val = parsed_tpl[var]
            if raw_val.startswith("passkey://"):
                mapped_vars[var] = raw_val
                lines.append(f"{var}={raw_val}")
                continue

            hits = lookup["matches"].get(var, [])
            exact_hits = [h for h in hits if h["match_type"] == "exact"]
            selected = None
            if len(exact_hits) == 1:
                selected = exact_hits[0]
            elif len(hits) == 1:
                selected = hits[0]

            if selected is not None:
                mapped_vars[var] = selected["reference"]
                lines.append(f"{var}={selected['reference']}")
            elif len(hits) > 1:
                refs = [h["reference"] for h in hits]
                ambiguous_vars[var] = refs
                lines.append(
                    f"# {var}={refs[0]}  # ambiguous: choose from {', '.join(refs)}"
                )
            else:
                missing_vars.append(var)
                lines.append(f"# {var}=passkey://<entry>/{var}  # missing in keychain")

        content = "\n".join(lines) + "\n"
        fd, tmp_path = tempfile.mkstemp(dir=root, prefix=".env-passkey-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(tmp_path, 0o644)
            os.replace(tmp_path, env_passkey_path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise
        written_files.append(str(env_passkey_path))

    if entries:
        env_files_cfg = [".env.passkey"] if (root / ".env.passkey").is_file() else []
        toml_written = write_passkey_toml(
            root,
            project_section={"entries": list(entries), "env_files": env_files_cfg},
        )
        written_files.append(str(toml_written))

    manifest = discover_project_manifest(root)
    assert manifest is not None

    trusted = False
    if not no_trust and can_prompt_interactively():
        _record_project_trust(manifest)
        trusted = True

    log_operation(
        "project_init",
        details={"manifests": manifest["manifests"], "count": len(mapped_vars)},
    )

    return {
        "ok": True,
        "project_root": str(root),
        "source_template": str(chosen_template) if chosen_template else None,
        "written_files": written_files,
        "manifests": manifest["manifests"],
        "manifest_sha256": manifest["manifest_sha256"],
        "trusted": trusted,
        "mapped_vars": mapped_vars,
        "ambiguous_vars": ambiguous_vars,
        "missing_vars": missing_vars,
    }


def exec_with_project(
    command: list[str] | None,
    *,
    project_dir: str | Path | None = None,
    quiet: bool = False,
    no_masking: bool = False,
    dry_run: bool = False,
    strict: bool = True,
) -> int | dict:
    """Auto-discover project manifest, enforce HMAC trust, preflight, and execute command."""
    base = (Path(project_dir) if project_dir is not None else Path.cwd()).expanduser().resolve()
    manifest = discover_project_manifest(base)
    if manifest is None:
        raise PasskeyError(
            f"No .env.passkey or .passkey.toml found in '{base}' (or enclosing git root). "
            "Run 'passkey project init' or 'passkey run -q <entry> -- <command>'.",
            error_code="PROJECT_MANIFEST_NOT_FOUND",
            remediation_command="passkey project init",
        )

    if dry_run:
        return get_project_status(base, command=command)

    if not command:
        raise PasskeyError(
            "No command specified after -- (Usage: passkey exec -- <command>)",
            error_code="INVALID_USAGE",
            remediation_command="passkey exec -- <command>",
        )

    # 1. Enforce HMAC-signed repo trust before touching or resolving any keychain secrets
    ensure_project_trusted(manifest)

    # 2. Preflight validation when strict (default True)
    if strict:
        status = get_project_status(base, command=command)
        if status["entries_missing"]:
            miss_entry = status["entries_missing"][0]
            raise PasskeyError(
                f"Project manifest entry '{miss_entry}' was not found in keychain.",
                error_code="ENTRY_NOT_FOUND",
                entry=miss_entry,
                remediation_command=f"passkey request {miss_entry}",
            )
        if status["references_invalid"]:
            bad_ref = status["references_invalid"][0]
            reason = bad_ref["reason"]
            try:
                from .references import parse_reference

                r_ent, r_fld = parse_reference(bad_ref["reference"])
            except PasskeyError:
                r_ent, r_fld = None, None
            is_missing_ent = "not found" in reason and "field" not in reason
            raise PasskeyError(
                f"Invalid project secret reference '{bad_ref['reference']}': {reason}",
                error_code="ENTRY_NOT_FOUND" if is_missing_ent else "MISSING_FIELD",
                entry=r_ent,
                missing_fields=[r_fld] if r_fld else [],
                remediation_command=(
                    f"passkey request {r_ent} --fields {r_fld}"
                    if (r_ent and r_fld)
                    else "passkey project status --json"
                ),
            )
        if status["missing_required_vars"]:
            miss_req = status["missing_required_vars"]
            raise PasskeyError(
                f"Project manifest missing required variable(s): {', '.join(miss_req)}",
                error_code="MISSING_FIELD",
                missing_fields=miss_req,
                remediation_command=f"passkey find {' '.join(miss_req)} --json",
            )
        if not status["entries"] and status["references_checked"] == 0:
            raise PasskeyError(
                f"Project manifest in '{manifest['project_root']}' contains no entries or "
                "active passkey:// references yet.",
                error_code="NO_SECRETS_LOADED",
                remediation_command="passkey project status --json",
            )

    return run_with_secrets(
        manifest["entries"],
        command,
        no_masking=no_masking,
        quiet=quiet,
        strict=strict,
        env_files=manifest["env_files"],
    )
