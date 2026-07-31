"""Unified diagnostics for passkey and MCP configurations.

Single implementation behind ``passkey doctor`` (CLI human output),
``passkey doctor --deep`` (adds entry-age and bundle-permission checks),
and the ``passkey_doctor`` MCP tool (structured output). Depth is a flag,
not a fork.
"""

from datetime import datetime
from pathlib import Path

from .keychain import PasskeyError, get_all_entries, list_entries
from .mcp_config import (
    ADAPTERS,
    MCPConfigError,
    find_passkey_command,
    get_mcp_servers,
    get_server_security_status,
    load_config,
)

# Entries older than this are considered stale
STALE_DAYS = 90


def run_diagnostics(deep: bool = False) -> dict:
    """Run diagnostics and return structured results.

    Args:
        deep: Also run entry age analysis and bundle permission checks.

    Returns:
        Dict with checks (name/status/message entries), issues,
        recommendations, and summary counts.
    """
    checks: list[dict] = []
    issues: list[str] = []
    recommendations: list[str] = []

    # Check 1: passkey in PATH
    passkey_path = find_passkey_command()
    if passkey_path:
        checks.append({
            "name": "passkey_in_path",
            "status": "pass",
            "message": f"Passkey found at {passkey_path}",
        })
    else:
        checks.append({
            "name": "passkey_in_path",
            "status": "fail",
            "message": "Passkey not found in PATH",
        })
        issues.append("Passkey command not in PATH")
        recommendations.append("Install passkey: pip install passkey-mcp")

    # Check 2: Keychain access
    entries: list[str] = []
    try:
        entries = list_entries()
        checks.append({
            "name": "keychain_access",
            "status": "pass",
            "message": f"Keychain accessible ({len(entries)} entries)",
        })
    except PasskeyError as e:
        checks.append({
            "name": "keychain_access",
            "status": "fail",
            "message": f"Keychain access failed: {e}",
        })
        issues.append("Cannot access system keychain")
        recommendations.append("Check system keychain access permissions")

    # Check 3: Each tool's config
    for adapter_name, adapter in ADAPTERS.items():
        for config_path in adapter.get_all_existing_paths():
            try:
                config = load_config(config_path)
                servers = get_mcp_servers(config, adapter)
                checks.append({
                    "name": f"{adapter_name}_config",
                    "status": "pass",
                    "message": f"{adapter.display_name} config found ({len(servers)} servers)",
                })

                for name, server_config in servers.items():
                    status = get_server_security_status(name, server_config, entries, adapter)
                    if status["status"] == "broken":
                        issues.append(
                            f"Missing passkey entry for server '{name}' in {adapter.display_name}"
                        )
                        recommendations.append(
                            f"Run 'passkey init --tool {adapter_name}' to secure"
                        )
                    elif status["status"] == "exposed":
                        issues.append(
                            f"Server '{name}' has exposed secrets in {adapter.display_name}: "
                            f"{', '.join(status['exposed_secrets'])}"
                        )
                        recommendations.append(
                            f"Run 'passkey init --tool {adapter_name}' to secure"
                        )

            except (FileNotFoundError, MCPConfigError) as e:
                checks.append({
                    "name": f"{adapter_name}_config",
                    "status": "fail",
                    "message": f"{adapter.display_name} config invalid: {e}",
                })
                issues.append(f"{adapter.display_name} config is invalid")

    if deep:
        _deep_checks(checks, issues, recommendations)

    summary = {
        "passed": sum(1 for c in checks if c["status"] == "pass"),
        "failed": sum(1 for c in checks if c["status"] == "fail"),
        "warnings": sum(1 for c in checks if c["status"] == "warn"),
    }

    return {
        "checks": checks,
        "issues": issues,
        "recommendations": recommendations,
        "summary": summary,
    }


def _deep_checks(checks: list[dict], issues: list[str], recommendations: list[str]) -> None:
    """Deep-only checks: entry age analysis and bundle file permissions."""
    # Entry age analysis
    all_entries = get_all_entries()
    stale_entries = []
    now = datetime.now()

    for entry in all_entries:
        # Check last_rotated first, fall back to created
        reference_time = entry.last_rotated or entry.created
        if reference_time:
            try:
                ref_dt = datetime.fromisoformat(reference_time)
                days_old = (now - ref_dt).days
                if days_old >= STALE_DAYS:
                    stale_entries.append((entry.name, days_old, entry.last_rotated is not None))
            except ValueError:
                pass

    if stale_entries:
        checks.append({
            "name": "entry_age",
            "status": "warn",
            "message": f"{len(stale_entries)} entries older than {STALE_DAYS} days",
        })
        for name, days, has_rotation in sorted(stale_entries, key=lambda x: -x[1]):
            label = "last rotated" if has_rotation else "created"
            issues.append(f'Rotate "{name}" ({label} {days} days ago)')
            recommendations.append(f"Run 'passkey rotate {name}' to update timestamp")
    else:
        checks.append({
            "name": "entry_age",
            "status": "pass",
            "message": f"All entries rotated within {STALE_DAYS} days",
        })

    # Bundle file permissions (current directory)
    insecure_bundles = []
    for f in Path.cwd().glob("*.enc"):
        if f.is_file():
            try:
                mode = f.stat().st_mode
                if mode & 0o077:  # Group or other has any permissions
                    insecure_bundles.append((str(f), oct(mode)[-3:]))
            except OSError:
                pass

    if insecure_bundles:
        checks.append({
            "name": "bundle_permissions",
            "status": "warn",
            "message": f"{len(insecure_bundles)} bundle file(s) with insecure permissions",
        })
        for path, perms in insecure_bundles:
            issues.append(f"Insecure permissions on {path}: {perms}")
            recommendations.append(f"Fix: chmod 600 '{path}'")
    else:
        checks.append({
            "name": "bundle_permissions",
            "status": "pass",
            "message": "No insecure bundle files detected",
        })
