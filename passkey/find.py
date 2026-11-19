"""Reverse environment-variable lookup across passkey entries without reading values."""

import re
from pathlib import Path

from .hooks import is_sensitive_secret_path
from .keychain import PasskeyError, get_all_entries
from .leases import peek_all_leases
from .plugins import PLUGIN_SPECS
from .references import parse_dotenv_file

_ENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

_GENERIC_FIELD_NAMES = frozenset(
    {
        "API_KEY",
        "API_TOKEN",
        "AUTH_TOKEN",
        "KEY",
        "PASSWORD",
        "PAT",
        "SECRET",
        "SECRET_KEY",
        "TOKEN",
    }
)

_EXTRA_SPECIFIC_SYNONYM_GROUPS: tuple[tuple[str, ...], ...] = (
    ("DATABASE_URL", "POSTGRES_URL", "POSTGRESQL_URL"),
    ("AWS_REGION", "AWS_DEFAULT_REGION"),
)


def _build_specific_synonyms() -> dict[str, set[str]]:
    """Build bidirectional map of service-specific env var synonyms."""
    groups: list[set[str]] = [set(g) for g in _EXTRA_SPECIFIC_SYNONYM_GROUPS]
    for spec in PLUGIN_SPECS.values():
        aliases_map: dict[str, list[str]] = spec.get("aliases", {})
        for canonical, alts in aliases_map.items():
            specific_alts = {a for a in alts if a not in _GENERIC_FIELD_NAMES}
            if specific_alts:
                groups.append({canonical, *specific_alts})

    synonym_map: dict[str, set[str]] = {}
    for grp in groups:
        for var in grp:
            bucket = synonym_map.setdefault(var, set())
            bucket.update(grp - {var})
    return synonym_map


_SPECIFIC_SYNONYMS = _build_specific_synonyms()


def _normalize_token(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").upper()


def _entry_matches_service_prefix(entry_name: str, prefix: str) -> bool:
    """Return True if entry_name corresponds to service prefix (e.g. 'resend' or 'resend_prod')."""
    norm_entry = _normalize_token(entry_name)
    norm_prefix = _normalize_token(prefix)
    if not norm_entry or not norm_prefix:
        return False
    return (
        norm_entry == norm_prefix
        or norm_entry.startswith(f"{norm_prefix}_")
        or norm_prefix.startswith(f"{norm_entry}_")
    )


def extract_var_names_from_template_file(file_path: str | Path) -> list[str]:
    """Extract env var names from a safe template file (.env.example, .env.template, etc.)."""
    raw_str = str(file_path)
    if is_sensitive_secret_path(raw_str):
        raise PasskeyError(
            f"Refusing to read sensitive secret file '{file_path}'. "
            "Pass a safe template such as '.env.example' or '.env.template'.",
            error_code="SENSITIVE_FILE_REFUSED",
            remediation_command="passkey find --from-file .env.example --json",
        )

    path = Path(file_path).expanduser()
    parsed = parse_dotenv_file(path)
    return list(parsed.keys())


def find_env_vars(
    var_names: list[str] | None = None,
    *,
    from_file: str | Path | None = None,
) -> dict:
    """Locate keychain entries and field names matching requested environment variables.

    Never logs a secret read, never consumes active leases, and never returns
    secret or config values.
    """
    queried: list[str] = []
    seen: set[str] = set()

    for raw in var_names or []:
        cleaned = raw.strip()
        if not cleaned:
            continue
        if not _ENV_VAR_NAME_RE.match(cleaned):
            raise PasskeyError(
                f"Invalid environment variable name '{cleaned}'.",
                error_code="INVALID_USAGE",
            )
        if cleaned not in seen:
            seen.add(cleaned)
            queried.append(cleaned)

    if from_file is not None:
        for file_var in extract_var_names_from_template_file(from_file):
            if file_var not in seen:
                seen.add(file_var)
                queried.append(file_var)

    if not queried:
        raise PasskeyError(
            "Specify at least one environment variable name or --from-file <path>.",
            error_code="INVALID_USAGE",
            remediation_command="passkey find <ENV_VAR> --json",
        )

    entries = get_all_entries(log_read=False)
    entries.sort(key=lambda e: e.name)
    active_leases = peek_all_leases()

    # Precompute plugin-backed entry aliases: (entry_names, target_var) -> list[generic_alt]
    plugin_generic_rules: dict[str, list[tuple[set[str], list[str]]]] = {}
    for cli_name, spec in PLUGIN_SPECS.items():
        candidate_entry_names = {cli_name, spec["default_entry"]}
        for canonical, alts in spec.get("aliases", {}).items():
            generic_alts = [a for a in alts if a in _GENERIC_FIELD_NAMES]
            if generic_alts:
                plugin_generic_rules.setdefault(canonical, []).append(
                    (candidate_entry_names, generic_alts)
                )

    matches_by_var: dict[str, list[dict]] = {}
    flat_results: list[dict] = []
    resolved_entries: set[str] = set()
    missing_vars: list[str] = []

    def _record_hit(
        req_var: str,
        var_hits_list: list[dict],
        seen_pairs: set[tuple[str, str]],
        entry_obj,
        matched_field: str,
        kind: str,
        match_type: str,
    ) -> None:
        pair = (entry_obj.name, matched_field)
        if pair in seen_pairs:
            return
        seen_pairs.add(pair)
        has_lease = entry_obj.name in active_leases
        policy = getattr(entry_obj, "policy", "allow")
        will_prompt = policy in ("prompt", "session") and not has_lease
        hit = {
            "requested_var": req_var,
            "entry": entry_obj.name,
            "field": matched_field,
            "kind": kind,
            "match_type": match_type,
            "policy": policy,
            "has_active_lease": has_lease,
            "will_prompt_biometric": will_prompt,
            "reference": f"passkey://{entry_obj.name}/{matched_field}",
        }
        var_hits_list.append(hit)
        flat_results.append(hit)
        resolved_entries.add(entry_obj.name)

    for target_var in queried:
        target_upper = target_var.upper()
        var_hits: list[dict] = []
        seen_entry_field: set[tuple[str, str]] = set()

        # Pass 1: Exact key match (case-exact first, then case-insensitive) across fields & config
        for ent in entries:
            if target_var in ent.fields:
                _record_hit(target_var, var_hits, seen_entry_field, ent, target_var, "secret", "exact")
            elif target_var in ent.config:
                _record_hit(target_var, var_hits, seen_entry_field, ent, target_var, "config", "exact")
            else:
                for k in sorted(ent.fields):
                    if k.upper() == target_upper:
                        _record_hit(target_var, var_hits, seen_entry_field, ent, k, "secret", "exact")
                for k in sorted(ent.config):
                    if k.upper() == target_upper:
                        _record_hit(target_var, var_hits, seen_entry_field, ent, k, "config", "exact")

        # Pass 2: Service-specific synonym match (e.g., GH_TOKEN <-> GITHUB_TOKEN)
        specific_alts = _SPECIFIC_SYNONYMS.get(target_upper, set())
        if specific_alts:
            for ent in entries:
                for k in sorted(ent.fields):
                    if k.upper() in specific_alts:
                        _record_hit(target_var, var_hits, seen_entry_field, ent, k, "secret", "alias")
                for k in sorted(ent.config):
                    if k.upper() in specific_alts:
                        _record_hit(target_var, var_hits, seen_entry_field, ent, k, "config", "alias")

        # Pass 3: Entry-scoped generic aliases (plugin specs + <SERVICE>_<GENERIC_FIELD> stem)
        for ent in entries:
            for allowed_entries, generic_alts in plugin_generic_rules.get(target_upper, []):
                if ent.name.lower() in {n.lower() for n in allowed_entries} or any(
                    _entry_matches_service_prefix(ent.name, n) for n in allowed_entries
                ):
                    for alt in generic_alts:
                        if alt in ent.fields:
                            _record_hit(target_var, var_hits, seen_entry_field, ent, alt, "secret", "entry_alias")
                        elif alt in ent.config:
                            _record_hit(target_var, var_hits, seen_entry_field, ent, alt, "config", "entry_alias")

            if "_" in target_upper:
                for generic_suffix in sorted(_GENERIC_FIELD_NAMES, key=len, reverse=True):
                    suffix_token = f"_{generic_suffix}"
                    if target_upper.endswith(suffix_token):
                        service_prefix = target_upper[: -len(suffix_token)]
                        if service_prefix and _entry_matches_service_prefix(
                            ent.name, service_prefix
                        ):
                            for k in sorted(ent.fields):
                                if k.upper() == generic_suffix:
                                    _record_hit(target_var, var_hits, seen_entry_field, ent, k, "secret", "entry_alias")
                            for k in sorted(ent.config):
                                if k.upper() == generic_suffix:
                                    _record_hit(target_var, var_hits, seen_entry_field, ent, k, "config", "entry_alias")

        matches_by_var[target_var] = var_hits
        if not var_hits:
            missing_vars.append(target_var)

    sorted_entries = sorted(resolved_entries)
    return {
        "ok": True,
        "all_found": len(missing_vars) == 0,
        "queried": queried,
        "matches": matches_by_var,
        "results": flat_results,
        "resolved_entries": sorted_entries,
        "missing_vars": missing_vars,
        "suggested_run_command": (
            f"passkey run -q {' '.join(sorted_entries)} -- <command>"
            if sorted_entries
            else None
        ),
    }


def cmd_find(
    var_names: list[str] | None = None,
    *,
    from_file: str | None = None,
    json_output: bool = False,
) -> None:
    """CLI handler for ``passkey find``."""
    import json

    report = find_env_vars(var_names, from_file=from_file)
    if json_output:
        print(json.dumps(report, indent=2))
        return

    for var in report["queried"]:
        hits = report["matches"].get(var, [])
        if not hits:
            print(f"  MISSING  {var}")
            continue
        for h in hits:
            tag = "" if h["match_type"] == "exact" else f" [{h['match_type']}]"
            pol = f" (policy={h['policy']})" if h["policy"] != "allow" else ""
            print(f"  FOUND    {var} -> {h['reference']}{tag}{pol}")

    if report["suggested_run_command"]:
        print(f"\nRun with: {report['suggested_run_command']}")
    if report["missing_vars"]:
        missing_csv = ",".join(report["missing_vars"])
        print(
            f"Missing ({len(report['missing_vars'])}): {', '.join(report['missing_vars'])} "
            f"(capture with: passkey request <entry> --fields {missing_csv})"
        )
