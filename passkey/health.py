"""Secret lifecycle commands for passkey (rotate, audit summary).

Diagnostics live in doctor.py — ``passkey doctor --deep`` is the CLI
entry point; there is no separate deep-doctor implementation here.
"""

from datetime import datetime, timedelta

from .audit import get_recent_logs
from .keychain import PasskeyError, get_all_entry_metas, get_entry


def cmd_rotate(
    entry_name: str,
    field_name: str | None = None,
    *,
    touch_only: bool = False,
) -> None:
    """Rotate a field value (or mark entry rotated) and update last_rotated.

    Args:
        entry_name: Name of the entry to rotate
        field_name: Optional field name to update using masked input
        touch_only: When True, update last_rotated without prompting for field values
    """
    from .interactive import format_secret_preview, is_interactive, prompt_secret, select_field
    from .keychain import save_entry

    entry = get_entry(entry_name)
    if not entry:
        raise PasskeyError(
            f"Entry '{entry_name}' not found. "
            f"Ask the user to run 'passkey new {entry_name}' in their terminal."
        )

    if touch_only:
        entry.rotate()
        save_entry(entry, is_update=True)
        print(f"Marked '{entry_name}' as rotated ({entry.last_rotated})")
        return

    target_field = field_name
    if target_field is None and entry.fields:
        if len(entry.fields) == 1:
            target_field = next(iter(entry.fields))
        elif is_interactive():
            target_field = select_field(
                entry_name, prompt="Select field to rotate", allow_empty=True
            )
            if target_field is None:
                print("Cancelled")
                return
        else:
            raise PasskeyError(
                f"Multiple fields in '{entry_name}' ({', '.join(sorted(entry.fields))}). "
                f"Specify a field name or pass --touch-only."
            )
    elif target_field is None and not entry.fields:
        raise PasskeyError(
            f"Entry '{entry_name}' has no secret fields to rotate. "
            "Pass --touch-only to update the rotation timestamp."
        )

    if target_field:
        try:
            new_value = prompt_secret(f"  New value for {target_field}")
        except EOFError as e:
            raise PasskeyError(
                f"No secret value provided for '{target_field}'; rotation aborted. "
                "Pass --touch-only to update the rotation timestamp without changing values."
            ) from e
        if not new_value:
            raise PasskeyError(
                f"Empty value provided for '{target_field}'; rotation aborted. "
                "Pass --touch-only to update the rotation timestamp without changing values."
            )
        entry.fields[target_field] = new_value
        print(f"  Updated '{target_field}' {format_secret_preview(new_value)}")

    entry.rotate()
    save_entry(entry, is_update=True)

    print(f"Marked '{entry_name}' as rotated ({entry.last_rotated})")


def cmd_audit_summary(*, json_output: bool = False) -> None:
    """Show aggregate audit log summary for the last 30 days."""
    import json

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

    # Get oldest entry regardless of recent logs (0 Keychain reads)
    all_entries = get_all_entry_metas(hydrate_unmigrated=False)
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

    days_old = (now - oldest_date).days if (oldest_entry and oldest_date) else None

    # Count operations by type
    op_counts: dict[str, int] = {}
    entry_access_counts: dict[str, int] = {}

    for log in recent:
        op = log.get("operation", "unknown")
        entry_name = log.get("entry", "")

        op_counts[op] = op_counts.get(op, 0) + 1

        if entry_name and op == "read":
            entry_access_counts[entry_name] = entry_access_counts.get(entry_name, 0) + 1

    most_accessed = (
        max(entry_access_counts, key=entry_access_counts.get) if entry_access_counts else None
    )

    if json_output:
        print(
            json.dumps(
                {
                    "window_days": 30,
                    "total_operations": sum(op_counts.values()),
                    "operations": dict(sorted(op_counts.items(), key=lambda x: -x[1])),
                    "most_accessed": most_accessed,
                    "entry_read_counts": entry_access_counts,
                    "oldest_entry": oldest_entry,
                    "oldest_entry_days": days_old,
                },
                indent=2,
            )
        )
        return

    if not recent:
        print("No audit log entries in the last 30 days")
        return

    # Print summary
    print("Audit Summary (last 30 days)")
    print("=" * 35)
    print()
    print("Operations:")
    for op, count in sorted(op_counts.items(), key=lambda x: -x[1]):
        print(f"  {op:12} {count:>5}")
    print(f"  {'TOTAL':12} {sum(op_counts.values()):>5}")

    if most_accessed:
        print()
        print(f"Most accessed: {most_accessed} ({entry_access_counts[most_accessed]} reads)")

    if oldest_entry and days_old is not None:
        print(f"Oldest entry:  {oldest_entry} (created {days_old} days ago)")
