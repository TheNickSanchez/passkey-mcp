"""CLI command handlers for passkey."""

import getpass
import json
import os
from datetime import datetime
from pathlib import Path

from .audit import clear_logs, get_recent_logs, log_operation
from .clipboard import copy_with_autoclear
from .keychain import (
    PasskeyError,
    delete_entry,
    get_all_entries,
    get_entry,
    list_entries,
    save_entry,
)
from .models import RESERVED_NAMES, Entry


def cmd_get_interactive(entry: Entry) -> None:
    """Interactive key picker - select fields to copy to clipboard."""
    if not entry:
        raise PasskeyError("Entry not found")

    if not entry.fields:
        print(f"Entry '{entry.name}' has no fields")
        return

    field_names = list(entry.fields.keys())
    print(f"\nEntry: {entry.name}\n" + "-" * 30)
    for i, name in enumerate(field_names, 1):
        print(f"  {i}. {name}")
    print("\nEnter number to copy value, or 'q' to quit\n")

    while True:
        choice = input("Select: ").strip().lower()
        if choice in ("q", "quit", "exit", ""):
            print("Exited")
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(field_names):
                field_name = field_names[idx]
                value = entry.fields[field_name]
                copy_with_autoclear(value, timeout_seconds=30)
                print(f"Copied '{field_name}' to clipboard (auto-clears in 30s)\n")
            else:
                print(f"Invalid selection. Enter 1-{len(field_names)}")
        except ValueError:
            print(f"Enter a number 1-{len(field_names)}, or 'q' to quit")


def _entry_edit_loop(
    name: str,
    fields: dict,
    config: dict,
    *,
    allow_rename: bool = True,
    original_name: str | None = None,
    original_created: str | None = None,
    original_source: str | None = None,
) -> tuple[str, dict, dict] | None:
    """Shared interactive edit loop used by both --new and --edit.

    Returns (final_name, fields, config) on Save, or None if the user quits.
    """
    import questionary

    from .interactive import PASSKEY_STYLE

    while True:
        print(f"\n  entry: {name}")
        if fields:
            for k in sorted(fields):
                print(f"    {k}")
        else:
            print("    (no fields — add at least one before saving)")
        print()

        choices = [
            questionary.Choice("Add field", "add"),
            questionary.Choice("Edit field value", "edit_val"),
            questionary.Choice("Rename field", "rename_field"),
            questionary.Choice("Delete field", "delete_field"),
        ]
        if allow_rename:
            choices += [
                questionary.Separator(),
                questionary.Choice("Rename entry", "rename_entry"),
            ]
        choices += [
            questionary.Separator(),
            questionary.Choice("Save & exit", "save"),
            questionary.Choice("Quit without saving", "quit"),
        ]

        action = questionary.select(
            "Action", choices=choices, style=PASSKEY_STYLE, use_jk_keys=False
        ).ask()

        if action is None or action == "quit":
            print("No changes saved.")
            return None

        elif action == "add":
            field_name = questionary.text("Field name:").ask()
            if field_name:
                value = getpass.getpass(f"  Value for {field_name}: ")
                fields[field_name] = value

        elif action == "edit_val":
            if not fields:
                print("  No fields to edit.")
                continue
            field_name = questionary.select(
                "Select field", choices=sorted(fields), style=PASSKEY_STYLE, use_jk_keys=False
            ).ask()
            if field_name:
                value = getpass.getpass(f"  New value for {field_name}: ")
                fields[field_name] = value

        elif action == "rename_field":
            if not fields:
                print("  No fields to rename.")
                continue
            field_name = questionary.select(
                "Select field", choices=sorted(fields), style=PASSKEY_STYLE, use_jk_keys=False
            ).ask()
            if field_name:
                new_field = questionary.text(
                    f"New name for '{field_name}':", default=field_name
                ).ask()
                if new_field and new_field != field_name:
                    fields[new_field] = fields.pop(field_name)

        elif action == "delete_field":
            if not fields:
                print("  No fields to delete.")
                continue
            field_name = questionary.select(
                "Select field", choices=sorted(fields), style=PASSKEY_STYLE, use_jk_keys=False
            ).ask()
            if field_name:
                confirmed = questionary.confirm(
                    f"Delete '{field_name}'?", default=False, style=PASSKEY_STYLE
                ).ask()
                if confirmed:
                    del fields[field_name]

        elif action == "rename_entry":
            new_name = questionary.text("New entry name:", default=name).ask()
            if new_name and new_name != name:
                name = new_name

        elif action == "save":
            if not fields:
                print("  Cannot save — add at least one field first.")
                continue
            break

    return name, fields, config


def cmd_new() -> None:
    """Create a new entry interactively."""
    import questionary

    from .interactive import is_interactive

    all_entry_names = list_entries()

    if is_interactive():
        name = questionary.text("Entry name:").ask()
    else:
        name = input("Entry name: ").strip()

    if not name:
        raise PasskeyError("Entry name cannot be empty")
    if name in RESERVED_NAMES:
        raise PasskeyError(f"'{name}' is a reserved name")

    is_update = False
    if name in all_entry_names:
        if is_interactive():
            overwrite = questionary.confirm(
                f"'{name}' already exists. Overwrite?", default=False
            ).ask()
        else:
            overwrite = input(f"Entry '{name}' exists. Overwrite? [y/N]: ").strip().lower() == "y"
        if not overwrite:
            print("Cancelled")
            return
        is_update = True

    if not is_interactive():
        # Non-interactive fallback: linear prompt
        fields: dict[str, str] = {}
        print("Enter fields (empty field name to finish):")
        while True:
            field_name = input("  Field name: ").strip()
            if not field_name:
                break
            fields[field_name] = getpass.getpass(f"  Value for {field_name}: ")
        if not fields:
            raise PasskeyError("No fields entered, operation cancelled.")
        entry = Entry(name=name, fields=fields)
        save_entry(entry, is_update=is_update)
        print(f"Saved '{name}' with {len(fields)} field(s)")
        return

    result = _entry_edit_loop(name, {}, {}, allow_rename=True)
    if result is None:
        return
    final_name, fields, config = result
    entry = Entry(name=final_name, fields=fields, config=config)
    save_entry(entry, is_update=is_update)
    print(f"Saved '{final_name}' with {len(fields)} field(s)")


def cmd_list(names_only: bool = False) -> None:
    """List all entries with field count and age."""
    entries = get_all_entries()
    if not entries:
        if not names_only:
            print("No entries found")
        return

    entries.sort(key=lambda e: e.name)

    if names_only:
        for e in entries:
            print(e.name)
        return

    name_w = max(len(e.name) for e in entries)
    now = datetime.now()

    for e in entries:
        field_count = len(e.fields) + len(e.config)
        fields_str = f"{field_count} field{'s' if field_count != 1 else ''}"

        age_str = ""
        if e.modified:
            try:
                modified = datetime.fromisoformat(e.modified)
                days = (now - modified).days
                if days == 0:
                    age_str = "today"
                elif days == 1:
                    age_str = "1 day ago"
                else:
                    age_str = f"{days}d ago"
            except ValueError:
                pass

        parts = [f"{e.name:<{name_w}}", f"  {fields_str:<12}"]
        if age_str:
            parts.append(f"  {age_str}")
        print("".join(parts))


def cmd_get_all(entry: Entry) -> None:
    """Copy all fields from entry to clipboard as key:value pairs."""
    if not entry:
        raise PasskeyError("Entry not found")

    output = "\n".join(f"{k}:{v}" for k, v in entry.fields.items())
    copy_with_autoclear(output, timeout_seconds=30)
    print(
        f"Copied {len(entry.fields)} field(s) from '{entry.name}' to clipboard (auto-clears in 30s)"
    )


def cmd_delete(entry_name: str) -> None:
    """Delete an entry from Keychain."""
    confirm = input(f"Delete entry '{entry_name}'? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled")
        return

    if delete_entry(entry_name):
        print(f"Deleted '{entry_name}'")
    else:
        # This case is now handled by the strict resolver in cli.py
        raise PasskeyError(f"Entry '{entry_name}' could not be deleted.")


def cmd_set_field(entry: Entry, field_name: str, value: str | None) -> None:
    """Upsert a single field on an existing entry."""
    if not entry:
        raise PasskeyError("Entry not found")
    if not field_name:
        raise PasskeyError("Field name cannot be empty")

    if value is None:
        value = getpass.getpass(f"  Value for {field_name}: ")

    action = "Updated" if field_name in entry.fields else "Added"
    fields = {**entry.fields, field_name: value}
    save_entry(Entry(name=entry.name, fields=fields), is_update=True)
    print(f"{action} field '{field_name}' on '{entry.name}'")


def cmd_edit(entry: Entry) -> None:
    """Edit an existing entry with an interactive action menu."""
    if not entry:
        raise PasskeyError("Entry not found")

    from .interactive import is_interactive
    from .keychain import rename_entry

    if not is_interactive():
        _cmd_edit_noninteractive(entry)
        return

    result = _entry_edit_loop(
        entry.name,
        entry.fields.copy(),
        entry.config.copy(),
        allow_rename=True,
    )
    if result is None:
        return

    final_name, fields, config = result
    updated = Entry(
        name=final_name,
        fields=fields,
        config=config,
        created=entry.created,
        source=entry.source,
    )
    if final_name != entry.name:
        rename_entry(entry.name, updated)
        print(f"Renamed '{entry.name}' → '{final_name}' with {len(fields)} field(s)")
    else:
        save_entry(updated, is_update=True)
        print(f"Saved '{final_name}' with {len(fields)} field(s)")


def _cmd_edit_noninteractive(entry: Entry) -> None:
    """Fallback edit for non-TTY: append/overwrite fields only."""
    print(f"Editing '{entry.name}' (fields: {', '.join(entry.fields.keys())})")
    print("Enter fields (empty name to finish):")
    fields = entry.fields.copy()
    while True:
        field_name = input("  Field name: ").strip()
        if not field_name:
            break
        fields[field_name] = getpass.getpass(f"  Value for {field_name}: ")
    save_entry(
        Entry(
            name=entry.name,
            fields=fields,
            config=entry.config,
            created=entry.created,
            source=entry.source,
        ),
        is_update=True,
    )
    print(f"Saved '{entry.name}' with {len(fields)} field(s)")


def cmd_clone(source: Entry, dest_name: str | None = None) -> None:
    """Clone an entry, optionally under a new name, then open the edit menu."""
    import questionary

    from .interactive import is_interactive

    existing = list_entries()

    if dest_name is None:
        if is_interactive():
            dest_name = questionary.text("New entry name:", default=f"{source.name}_copy").ask()
        else:
            dest_name = (
                input(f"New entry name [{source.name}_copy]: ").strip() or f"{source.name}_copy"
            )

    if not dest_name:
        raise PasskeyError("Entry name cannot be empty")
    if dest_name in existing:
        raise PasskeyError(
            f"Entry '{dest_name}' already exists. Delete it first or choose a different name."
        )

    if not is_interactive():
        entry = Entry(name=dest_name, fields=source.fields.copy(), config=source.config.copy())
        save_entry(entry, is_update=False)
        print(f"Cloned '{source.name}' → '{dest_name}' with {len(entry.fields)} field(s)")
        return

    print(f"\nCloning '{source.name}' → '{dest_name}'")
    print("Fields copied — edit before saving:\n")

    result = _entry_edit_loop(
        dest_name, source.fields.copy(), source.config.copy(), allow_rename=True
    )
    if result is None:
        return

    final_name, fields, config = result
    if final_name != dest_name and final_name in existing:
        raise PasskeyError(f"Entry '{final_name}' already exists.")
    entry = Entry(name=final_name, fields=fields, config=config)
    save_entry(entry, is_update=False)
    print(f"Cloned '{source.name}' → '{final_name}' with {len(fields)} field(s)")


def cmd_check(entry_name: str, required_fields: list[str], quiet: bool = False) -> None:
    """Verify an entry has all required fields. Exits non-zero if any are missing."""
    import sys

    entry = get_entry(entry_name)

    if entry is None:
        if not quiet:
            print(f"MISSING  entry '{entry_name}' not found", file=sys.stderr)
        sys.exit(1)

    all_fields = set(entry.fields) | set(entry.config)
    missing = [f for f in required_fields if f not in all_fields]

    if not quiet:
        for f in required_fields:
            status = "OK      " if f in all_fields else "MISSING "
            print(f"  {status} {f}")

    if missing:
        if not quiet:
            print(f"\n{len(missing)} missing field(s) in '{entry_name}'", file=sys.stderr)
        sys.exit(1)
    else:
        if not quiet:
            print(f"\nAll {len(required_fields)} field(s) present in '{entry_name}'")


def cmd_info(entry: Entry) -> None:
    """Show entry details including metadata and field names."""
    if not entry:
        raise PasskeyError("Entry not found")

    print(f"Entry: {entry.name}")
    print(f"Created: {entry.created or 'unknown'}")
    print(f"Modified: {entry.modified or 'unknown'}")
    print(f"Source: {entry.source or 'unknown'}")
    print(f"\nFields ({len(entry.fields)}):")
    for key in sorted(entry.fields.keys()):
        print(f"  {key}")


def cmd_export(file_path: str, entries: list[str] | None = None, no_secrets: bool = False) -> None:
    """Export entries to JSON file."""
    all_entries = get_all_entries()
    if not all_entries:
        print("No entries to export")
        return

    if entries:
        entry_set = set(entries)
        all_entries = [e for e in all_entries if e.name in entry_set]
        if not all_entries:
            raise PasskeyError("No matching entries found for export.")

    export_data = {
        "version": "1.0",
        "exported_at": datetime.now().isoformat(),
        "entry_count": len(all_entries),
        "entries": [e.to_export_dict(no_secrets) for e in all_entries],
    }

    json_str = json.dumps(export_data, indent=2)

    if file_path == "-":
        if not no_secrets:
            confirm = (
                input(
                    "WARNING: This will print secrets to stdout (visible in terminal history).\n"
                    "Continue? [y/N]: "
                )
                .strip()
                .lower()
            )
            if confirm != "y":
                print("Cancelled")
                return
        print(json_str)
    else:
        path = Path(file_path).expanduser()
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(json_str)
            print(f"Exported {len(all_entries)} entry(s) to {path}")
            if not no_secrets:
                print("Warning: Export contains secrets. File permissions set to 600 (owner only).")
        except FileExistsError:
            raise PasskeyError(
                f"File already exists at '{path}'. Please remove it first."
            ) from None
        except OSError as e:
            raise PasskeyError(f"Error writing to file: {e}") from e

    log_operation("export", details={"count": len(all_entries), "no_secrets": no_secrets})


def cmd_audit(limit: int = 20, clear: bool = False) -> None:
    """View or clear audit log."""
    if clear:
        confirm = input("Clear audit log? [y/N]: ").strip().lower()
        if confirm == "y":
            if not clear_logs():
                raise PasskeyError("Failed to clear audit log")
            print("Audit log cleared")
        else:
            print("Cancelled")
        return

    logs = get_recent_logs(limit)
    if not logs:
        print("No audit log entries")
        return

    print(f"Recent operations (last {len(logs)}):\n")
    for log in logs:
        ts = log.get("timestamp", "")[:19].replace("T", " ")
        op = log.get("operation", "?")
        entry = log.get("entry", "")
        success = "OK" if log.get("success", True) else "FAIL"
        details_str = ", ".join(
            f"{k}={v}" for k, v in log.get("details", {}).items() if k != "error"
        )
        line = f"[{ts}] {op.upper():8s} {success:4s} {entry}"
        if details_str:
            line += f" ({details_str})"
        print(line)
