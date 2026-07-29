"""Secret lifecycle and health diagnostics for passkey."""

from datetime import datetime, timedelta
from pathlib import Path

from .audit import get_recent_logs
from .keychain import PasskeyError, get_all_entries, get_entry, list_entries
from .mcp_config import (
    ADAPTERS,
    MCPConfigError,
    get_mcp_servers,
    get_server_security_status,
    load_config,
)

# Entries older than this are considered stale
STALE_DAYS = 90


def cmd_rotate(entry_name: str) -> None:
    """Mark an entry as rotated by updating its last_rotated timestamp.

    Args:
        entry_name: Name of the entry to rotate
    """
    entry = get_entry(entry_name)
    if not entry:
        raise PasskeyError(f"Entry '{entry_name}' not found")

    entry.rotate()

    # Save with updated metadata
    from .keychain import save_entry
    save_entry(entry, is_update=True)

    print(f"Marked '{entry_name}' as rotated ({entry.last_rotated})")


def cmd_doctor_deep() -> None:
    """Extended diagnostics: entry age, exposed secrets, bundle permissions, config health."""
    print("Passkey Doctor (deep)")
    print("=" * 35)
    print()

    checks = []
    issues = []
    recommendations = []

    # Check 1: Passkey in PATH
    from .mcp_config import find_passkey_command
    passkey_path = find_passkey_command()
    if passkey_path:
        checks.append(("pass", f"Passkey found at {passkey_path}"))
    else:
        checks.append(("fail", "Passkey not found in PATH"))
        issues.append("Passkey command not in PATH")
        recommendations.append("Install passkey: pip install passkey-mcp")

    # Check 2: Keychain access
    try:
        entries = list_entries()
        checks.append(("pass", f"Keychain accessible ({len(entries)} entries)"))
    except PasskeyError as e:
        checks.append(("fail", f"Keychain access failed: {e}"))
        issues.append("Cannot access system keychain")
        recommendations.append("Check system keychain access permissions")
        return

    # Check 3: Entry age analysis
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
        stale_with_rotation = sum(1 for _, _, has_rotation in stale_entries if has_rotation)
        len(stale_entries) - stale_with_rotation
        checks.append(("warn", f"{len(stale_entries)} entries older than {STALE_DAYS} days"))
        for name, days, has_rotation in sorted(stale_entries, key=lambda x: -x[1]):
            label = "last rotated" if has_rotation else "created"
            issues.append(f'Rotate "{name}" ({label} {days} days ago)')
            recommendations.append(f"Run 'passkey rotate {name}' to update timestamp")
    else:
        checks.append(("pass", f"All entries rotated within {STALE_DAYS} days"))

    # Check 4: MCP config security
    for adapter in ADAPTERS.values():
        config_paths = adapter.get_all_existing_paths()
        if not config_paths:
            continue

        for config_path in config_paths:
            try:
                config = load_config(config_path)
                servers = get_mcp_servers(config, adapter)
                checks.append(("pass", f"{adapter.display_name} config found ({len(servers)} servers)"))

                for name, server_config in servers.items():
                    status = get_server_security_status(name, server_config, entries, adapter)
                    if status["status"] == "exposed":
                        issues.append(
                            f"Server '{name}' has exposed secrets in {adapter.display_name}: "
                            f"{', '.join(status['exposed_secrets'])}"
                        )
                        recommendations.append(
                            f"Run 'passkey init --tool {adapter.name}' to secure"
                        )
                    elif status["status"] == "broken":
                        issues.append(
                            f"Missing passkey entry for server '{name}' in {adapter.display_name}"
                        )
                        recommendations.append(
                            f"Run 'passkey init --tool {adapter.name}' to secure"
                        )
            except MCPConfigError as e:
                checks.append(("fail", f"{adapter.display_name} config invalid: {e}"))

    # Check 5: Bundle file permissions
    from .dirs import get_data_dir
    get_data_dir()
    insecure_bundles = []

    # Check current directory for .enc files
    for f in Path.cwd().glob("*.enc"):
        if f.is_file():
            try:
                mode = f.stat().st_mode
                if mode & 0o077:  # Group or other has any permissions
                    insecure_bundles.append((str(f), oct(mode)[-3:]))
            except OSError:
                pass

    if insecure_bundles:
        checks.append(("warn", f"{len(insecure_bundles)} bundle file(s) with insecure permissions"))
        for path, perms in insecure_bundles:
            issues.append(f"Insecure permissions on {path}: {perms}")
            recommendations.append(f"Fix: chmod 600 '{path}'")
    else:
        checks.append(("pass", "No insecure bundle files detected"))

    # Print results
    for status, message in checks:
        if status == "pass":
            symbol = "\u2713"
        elif status == "warn":
            symbol = "\u26a0"
        else:
            symbol = "\u2717"
        print(f"  {symbol} {message}")

    if issues:
        print()
        print(f"Issues found: {len(issues)}")
        print()
        print("Recommendations:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    else:
        print()
        print("All checks passed!")


def cmd_audit_summary() -> None:
    """Show aggregate audit log summary."""
    logs = get_recent_logs(limit=1000)

    if not logs:
        print("No audit log entries")
        return

    # Count operations by type
    op_counts: dict[str, int] = {}
    entry_access_counts: dict[str, int] = {}
    now = datetime.now()
    now - timedelta(days=30)

    for log in logs:
        op = log.get("operation", "unknown")
        entry = log.get("entry", "")
        log.get("timestamp", "")

        op_counts[op] = op_counts.get(op, 0) + 1

        if entry and op == "read":
            entry_access_counts[entry] = entry_access_counts.get(entry, 0) + 1

    # Get oldest entry
    all_entries = get_all_entries()
    oldest_entry = None
    oldest_date = None

    for entry in all_entries:
        if entry.created:
            try:
                created = datetime.fromisoformat(entry.created)
                if oldest_date is None or created < oldest_date:
                    oldest_date = created
                    oldest_entry = entry.name
            except ValueError:
                pass

    # Print summary
    print("Audit Summary (last 30 days)")
    print("=" * 35)
    print()
    print("Operations:")
    for op, count in sorted(op_counts.items(), key=lambda x: -x[1]):
        print(f"  {op:12} {count:>5}")
    print(f"  {'TOTAL':12} {sum(op_counts.values()):>5}")

    if entry_access_counts:
        print()
        most_accessed = max(entry_access_counts, key=entry_access_counts.get)
        print(f"Most accessed: {most_accessed} ({entry_access_counts[most_accessed]} reads)")

    if oldest_entry and oldest_date:
        days_old = (now - oldest_date).days
        print(f"Oldest entry:  {oldest_entry} (created {days_old} days ago)")
