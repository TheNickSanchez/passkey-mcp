"""Secret lifecycle commands for passkey (rotate, audit summary).

Diagnostics live in doctor.py — ``passkey doctor --deep`` is the CLI
entry point; there is no separate deep-doctor implementation here.
"""

from datetime import datetime, timedelta

from .audit import get_recent_logs
from .keychain import PasskeyError, get_all_entries, get_entry


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


def cmd_audit_summary() -> None:
    """Show aggregate audit log summary for the last 30 days."""
    logs = get_recent_logs(limit=1000)

    now = datetime.now()
    cutoff = now - timedelta(days=30)

    recent = []
    for log in logs:
        try:
            ts = datetime.fromisoformat(log.get("timestamp", ""))
        except ValueError:
            continue  # unparseable/missing timestamp: can't place it in the window
        if ts >= cutoff:
            recent.append(log)

    if not recent:
        print("No audit log entries in the last 30 days")
        return

    # Count operations by type
    op_counts: dict[str, int] = {}
    entry_access_counts: dict[str, int] = {}

    for log in recent:
        op = log.get("operation", "unknown")
        entry = log.get("entry", "")

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
