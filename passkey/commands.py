"""CLI command handlers for passkey."""

import contextlib
import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from .audit import clear_logs, get_recent_logs, log_operation, verify_audit_log
from .clipboard import copy_with_autoclear
from .keychain import (
    PasskeyError,
    _get_entry,
    delete_entry,
    get_all_entries,
    get_entry,  # noqa: F401 (re-exported for callers and test mocks)
    list_entries,
    save_entry,
)
from .models import ENTRY_NAME_PATTERN, RESERVED_NAMES, VALID_POLICIES, Entry


def cmd_get_interactive(entry: Entry) -> None:
    """Interactive key picker — auto-copies single fields or uses arrow-key picker."""
    if not entry:
        raise PasskeyError("Entry not found")

    if not entry.fields:
        print(f"Entry '{entry.name}' has no fields")
        return

    field_names = list(entry.fields.keys())

    # Single-field shortcut: copy immediately so `passkey -> Enter` is 1 step
    if len(field_names) == 1:
        field_name = field_names[0]
        copy_with_autoclear(entry.fields[field_name], timeout_seconds=30)
        print(f"Copied '{field_name}' from '{entry.name}' to clipboard (auto-clears in 30s)")
        return

    from .interactive import PASSKEY_STYLE, format_secret_preview, is_interactive

    if is_interactive():
        import questionary

        key_w = max(len(k) for k in field_names)
        choices: list = [
            questionary.Choice(
                f"{fname:<{key_w}}  {format_secret_preview(entry.fields[fname])}",
                value=fname,
            )
            for fname in field_names
        ]
        choices.extend(
            [
                questionary.Separator(),
                questionary.Choice("Copy all fields (KEY='value')", value="__all__"),
                questionary.Choice("(cancel)", value=None),
            ]
        )

        selected = questionary.select(
            f"Select field from '{entry.name}'",
            choices=choices,
            style=PASSKEY_STYLE,
            instruction="(Use arrow keys, type to filter)",
            use_jk_keys=False,
        ).ask()

        if selected is None:
            return
        if selected == "__all__":
            cmd_get_all(entry)
            return

        copy_with_autoclear(entry.fields[selected], timeout_seconds=30)
        print(f"Copied '{selected}' from '{entry.name}' to clipboard (auto-clears in 30s)")
        return

    # Non-TTY fallback for multi-field entries
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


def _print_entry_summary(name: str, fields: dict[str, str]) -> None:
    """Print entry name and non-sensitive masked previews of all fields."""
    from .interactive import format_secret_preview

    print(f"\n  entry: {name}")
    if fields:
        key_w = max(len(k) for k in fields)
        for k in sorted(fields):
            print(f"    {k:<{key_w}}  {format_secret_preview(fields[k])}")
    else:
        print("    (no fields — add at least one before saving)")
    print()


def _apply_template_into_fields(template: dict, fields: dict[str, str]) -> None:
    """Populate fields interactively or via fallback from a template dict."""
    from .generator import generate_password
    from .interactive import PASSKEY_STYLE, format_secret_preview, is_interactive, prompt_secret

    if is_interactive():
        import questionary

        for field_def in template.get("fields", []):
            fname = field_def["name"]
            secret = field_def.get("secret", False)
            generate = field_def.get("generate", False)

            if generate:
                use_gen = questionary.confirm(
                    f"Generate random value for {fname}?", default=True, style=PASSKEY_STYLE
                ).ask()
                if use_gen:
                    val = generate_password()
                    fields[fname] = val
                    print(f"  + {fname}  {format_secret_preview(val)} (generated)")
                    continue

            if secret:
                val = prompt_secret(f"  Value for {fname}")
            else:
                val = questionary.text(f"{fname}:", style=PASSKEY_STYLE).ask() or ""
            if val:
                fields[fname] = val
                if secret:
                    print(f"  + {fname}  {format_secret_preview(val)}")
    else:
        print(f"Template '{template['name']}' fields:")
        for field_def in template.get("fields", []):
            fname = field_def["name"]
            secret = field_def.get("secret", False)
            if secret:
                val = prompt_secret(f"  Value for {fname}")
            else:
                val = input(f"  {fname}: ").strip()
            if val:
                fields[fname] = val


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
    """Shared interactive edit loop used by both new and edit.

    Returns (final_name, fields, config) on Save, or None if the user quits.
    """
    import questionary

    from .generator import generate_password
    from .interactive import (
        PASSKEY_STYLE,
        format_secret_preview,
        parse_field_shorthand,
        prompt_secret,
    )
    from .templates import get_template, list_templates

    while True:
        _print_entry_summary(name, fields)

        choices = [
            questionary.Choice("Add field", "add"),
            questionary.Choice("Generate random value", "generate"),
            questionary.Choice("Apply template", "template"),
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
            lbl = "Field name (or KEY=VALUE; Enter to save):" if fields else "Field name (or KEY=VALUE):"
            raw_field = questionary.text(lbl, style=PASSKEY_STYLE).ask()
            if raw_field is None:
                continue
            if not raw_field.strip():
                if fields:
                    break
                continue
            field_name, inline_val = parse_field_shorthand(raw_field)
            if not field_name:
                print("  Field name cannot be empty.")
                continue
            value = (
                inline_val
                if inline_val is not None
                else prompt_secret(f"  Value for {field_name}")
            )
            fields[field_name] = value
            print(f"  + {field_name}  {format_secret_preview(value)}")

        elif action == "generate":
            raw_field = questionary.text("Field name:", style=PASSKEY_STYLE).ask()
            if raw_field and raw_field.strip():
                field_name = raw_field.strip()
                value = generate_password()
                fields[field_name] = value
                print(f"  + {field_name}  {format_secret_preview(value)} (generated)")

        elif action == "template":
            templates = list_templates()
            if not templates:
                print("  No templates found.")
                continue
            tname = questionary.select(
                "Select template",
                choices=[t["name"] for t in templates],
                style=PASSKEY_STYLE,
                instruction="(Type to filter)",
                use_jk_keys=False,
            ).ask()
            if tname:
                tpl = get_template(tname)
                if tpl:
                    _apply_template_into_fields(tpl, fields)

        elif action == "edit_val":
            if not fields:
                print("  No fields to edit.")
                continue
            field_name = questionary.select(
                "Select field", choices=sorted(fields), style=PASSKEY_STYLE, use_jk_keys=False
            ).ask()
            if field_name:
                value = prompt_secret(f"  New value for {field_name}")
                fields[field_name] = value
                print(f"  ~ {field_name}  {format_secret_preview(value)}")

        elif action == "rename_field":
            if not fields:
                print("  No fields to rename.")
                continue
            field_name = questionary.select(
                "Select field", choices=sorted(fields), style=PASSKEY_STYLE, use_jk_keys=False
            ).ask()
            if field_name:
                new_field = questionary.text(
                    f"New name for '{field_name}':", default=field_name, style=PASSKEY_STYLE
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
            new_name = questionary.text("New entry name:", default=name, style=PASSKEY_STYLE).ask()
            if new_name and new_name != name:
                name = new_name

        elif action == "save":
            if not fields:
                print("  Cannot save — add at least one field first.")
                continue
            break

    return name, fields, config


def _validate_entry_name(name: str | None) -> str:
    """Validate and normalize an entry name before prompting for fields."""
    if not name or not name.strip():
        raise PasskeyError("Entry name cannot be empty")
    cleaned = name.strip()
    if cleaned in RESERVED_NAMES:
        raise PasskeyError(f"'{cleaned}' is a reserved name")
    if not ENTRY_NAME_PATTERN.match(cleaned):
        raise PasskeyError(
            f"Invalid entry name '{cleaned}'. "
            "Names must be 1-64 chars: letters, digits, hyphens, underscores, dots."
        )
    return cleaned


def cmd_new(name: str | None = None, template_name: str | None = None) -> None:
    """Create a new entry with direct field input and zero default interruptions."""
    import questionary

    from .interactive import (
        PASSKEY_STYLE,
        format_secret_preview,
        is_interactive,
        parse_field_shorthand,
        prompt_secret,
        require_interactive,
    )

    if name is not None:
        name = _validate_entry_name(name)

    human_cmd = f"passkey new {name}" if name else "passkey new <name>"
    if template_name:
        human_cmd += f" --template {template_name}"
    require_interactive("passkey new", human_command=human_cmd)

    if template_name:
        from .templates import get_template

        template = get_template(template_name)
        if not template:
            raise PasskeyError(
                f"Template '{template_name}' not found. Run 'passkey template list' to see templates."
            )
        target_name = name
        if not target_name:
            if is_interactive():
                target_name = questionary.text(
                    "Entry name:", default=template["name"], style=PASSKEY_STYLE
                ).ask()
            else:
                target_name = template["name"]
        validated = _validate_entry_name(target_name)
        cmd_template_apply(template, validated)
        return

    all_entry_names = list_entries()

    if name is None:
        if is_interactive():
            raw_name = questionary.text("Entry name:", style=PASSKEY_STYLE).ask()
        else:
            raw_name = input("Entry name: ").strip()
    else:
        raw_name = name

    name = _validate_entry_name(raw_name)

    is_update = False
    if name in all_entry_names:
        if is_interactive():
            overwrite = questionary.confirm(
                f"'{name}' already exists. Overwrite?", default=False, style=PASSKEY_STYLE
            ).ask()
        else:
            overwrite = input(f"Entry '{name}' exists. Overwrite? [y/N]: ").strip().lower() == "y"
        if not overwrite:
            print("Cancelled")
            return
        is_update = True

    if not is_interactive():
        fields: dict[str, str] = {}
        print(f"Enter fields for '{name}' (KEY=VALUE or field name; empty name to save):")
        while True:
            try:
                raw_field = input("  Field name: ").strip()
            except EOFError:
                break
            if not raw_field:
                break
            field_name, inline_val = parse_field_shorthand(raw_field)
            if not field_name:
                print("  Field name cannot be empty.")
                continue
            value = (
                inline_val
                if inline_val is not None
                else prompt_secret(f"  Value for {field_name}")
            )
            fields[field_name] = value
            print(f"  + {field_name}  {format_secret_preview(value)}")
        if not fields:
            raise PasskeyError("No fields entered, operation cancelled.")
        _print_entry_summary(name, fields)
        entry = Entry(name=name, fields=fields)
        save_entry(entry, is_update=is_update)
        print(f"Saved '{name}' with {len(fields)} field(s)")
        return

    fields = {}
    config: dict[str, str] = {}
    open_editor = False
    print(f"\n  Adding fields to '{name}' (paste KEY=VALUE or enter field name; '?' for menu)")

    while True:
        prompt_lbl = (
            "Field name (Enter to save, '?' for menu):"
            if fields
            else "Field name ('?' for menu):"
        )
        raw_field = questionary.text(prompt_lbl, style=PASSKEY_STYLE).ask()
        if raw_field is None:
            print("Cancelled")
            return
        stripped = raw_field.strip()
        if stripped in ("?", "/menu"):
            open_editor = True
            break
        if not stripped:
            if fields:
                # Pressing Enter on an empty Field name after >= 1 field saves & exits cleanly
                break
            open_editor = True
            break

        field_name, inline_val = parse_field_shorthand(stripped)
        if not field_name:
            print("  Field name cannot be empty.")
            continue
        value = (
            inline_val
            if inline_val is not None
            else prompt_secret(f"  Value for {field_name}")
        )
        fields[field_name] = value
        print(f"  + {field_name}  {format_secret_preview(value)}")

    final_name = name
    if open_editor:
        result = _entry_edit_loop(name, fields, config, allow_rename=True)
        if result is None:
            return
        final_name, fields, config = result
        final_name = _validate_entry_name(final_name)
    else:
        _print_entry_summary(final_name, fields)

    if final_name != name and final_name in all_entry_names:
        raise PasskeyError(f"Entry '{final_name}' already exists.")

    entry = Entry(name=final_name, fields=fields, config=config)
    save_entry(entry, is_update=(is_update if final_name == name else False))
    print(f"Saved '{final_name}' with {len(fields)} field(s)")


def cmd_template_apply(template: dict, entry_name: str) -> None:
    """Create an entry from a template."""
    from .interactive import PASSKEY_STYLE, is_interactive
    from .keychain import list_entries
    from .keychain import save_entry as _save
    from .models import Entry

    all_names = list_entries()

    if entry_name in all_names:
        if is_interactive():
            import questionary

            overwrite = questionary.confirm(
                f"'{entry_name}' already exists. Overwrite?", default=False, style=PASSKEY_STYLE
            ).ask()
        else:
            overwrite = (
                input(f"Entry '{entry_name}' exists. Overwrite? [y/N]: ").strip().lower() == "y"
            )
        if not overwrite:
            print("Cancelled")
            return

    fields: dict[str, str] = {}
    _apply_template_into_fields(template, fields)

    if not fields:
        raise PasskeyError("No fields entered, operation cancelled.")

    _print_entry_summary(entry_name, fields)
    entry = Entry(name=entry_name, fields=fields, source=f"template:{template['name']}")
    _save(entry, is_update=entry_name in all_names)
    print(
        f"Created entry '{entry_name}' from template '{template['name']}' with {len(fields)} field(s)"
    )


def cmd_list(names_only: bool = False, *, json_output: bool = False) -> None:
    """List all entries with field count and age."""
    entries = get_all_entries()
    entries.sort(key=lambda e: e.name)

    if json_output:
        from .leases import peek_all_leases

        active_leases = peek_all_leases()
        payload = [
            {
                "name": e.name,
                "field_count": len(e.fields),
                "config_count": len(e.config),
                "fields": sorted(e.fields.keys()),
                "config_keys": sorted(e.config.keys()),
                "policy": e.policy,
                "has_active_lease": e.name in active_leases,
                "created": e.created,
                "modified": e.modified,
                "last_rotated": e.last_rotated,
                "source": e.source,
            }
            for e in entries
        ]
        print(json.dumps(payload, indent=2))
        return

    if not entries:
        if not names_only:
            print("No entries found")
        return

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


def _posix_single_quote(value: str) -> str:
    """Always wrap in single quotes. Embed apostrophes as POSIX '\\''."""
    return "'" + value.replace("'", "'\"'\"'") + "'"


def fields_as_env(fields: dict[str, str]) -> str:
    """Format fields as KEY='value' lines. Every value is quoted."""
    return "\n".join(f"{k}={_posix_single_quote(v)}" for k, v in fields.items())


def cmd_get_all(entry: Entry) -> None:
    """Copy all fields to the clipboard as KEY='value' lines."""
    if not entry:
        raise PasskeyError("Entry not found")

    copy_with_autoclear(fields_as_env(entry.fields), timeout_seconds=30)
    print(
        f"Copied {len(entry.fields)} field(s) from '{entry.name}' to clipboard (auto-clears in 30s)"
    )


def cmd_delete(entry_name: str, *, yes: bool = False) -> None:
    """Delete an entry from Keychain."""
    if not yes:
        confirm = input(f"Delete entry '{entry_name}'? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Cancelled")
            return

    if delete_entry(entry_name):
        print(f"Deleted '{entry_name}'")
    else:
        raise PasskeyError(f"Entry '{entry_name}' could not be deleted.")


def cmd_set_field(entry: Entry, field_name: str, value: str | None) -> None:
    """Upsert a single field on an existing entry."""
    from .interactive import format_secret_preview, prompt_secret

    if not entry:
        raise PasskeyError("Entry not found")
    if not field_name:
        raise PasskeyError("Field name cannot be empty")

    if value is None:
        value = prompt_secret(f"  Value for {field_name}")

    action = "Updated" if field_name in entry.fields else "Added"
    # Mutate the existing entry so config/created/source are preserved
    entry.fields[field_name] = value
    save_entry(entry, is_update=True)
    print(f"{action} field '{field_name}' on '{entry.name}' {format_secret_preview(value)}")


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
    final_name = _validate_entry_name(final_name)
    updated = Entry(
        name=final_name,
        fields=fields,
        config=config,
        created=entry.created,
        source=entry.source,
        last_rotated=entry.last_rotated,
        policy=entry.policy,
    )
    if final_name != entry.name:
        rename_entry(entry.name, updated)
        print(f"Renamed '{entry.name}' → '{final_name}' with {len(fields)} field(s)")
    else:
        save_entry(updated, is_update=True)
        print(f"Saved '{final_name}' with {len(fields)} field(s)")


def _cmd_edit_noninteractive(entry: Entry) -> None:
    """Fallback edit for non-TTY: append/overwrite fields only."""
    from .interactive import format_secret_preview, parse_field_shorthand, prompt_secret

    print(f"Editing '{entry.name}' (fields: {', '.join(entry.fields.keys())})")
    print("Enter fields (KEY=VALUE or field name; empty name to finish):")
    fields = entry.fields.copy()
    mutated = False
    while True:
        try:
            raw_field = input("  Field name: ").strip()
        except EOFError:
            break
        if not raw_field:
            break
        field_name, inline_val = parse_field_shorthand(raw_field)
        if not field_name:
            print("  Field name cannot be empty.")
            continue
        value = (
            inline_val
            if inline_val is not None
            else prompt_secret(f"  Value for {field_name}")
        )
        fields[field_name] = value
        mutated = True
        print(f"  ~ {field_name}  {format_secret_preview(value)}")
    if not mutated:
        raise PasskeyError("No fields entered, edit cancelled.")
    save_entry(
        Entry(
            name=entry.name,
            fields=fields,
            config=entry.config,
            created=entry.created,
            source=entry.source,
            last_rotated=entry.last_rotated,
            policy=entry.policy,
        ),
        is_update=True,
    )
    print(f"Saved '{entry.name}' with {len(fields)} field(s)")


def cmd_clone(source: Entry, dest_name: str | None = None) -> None:
    """Clone an entry, optionally under a new name, then open the edit menu."""
    import questionary

    from .interactive import PASSKEY_STYLE, is_interactive

    existing = list_entries()

    if dest_name is None:
        if is_interactive():
            dest_name = questionary.text(
                "New entry name:", default=f"{source.name}_copy", style=PASSKEY_STYLE
            ).ask()
        else:
            dest_name = (
                input(f"New entry name [{source.name}_copy]: ").strip() or f"{source.name}_copy"
            )

    dest_name = _validate_entry_name(dest_name)
    if dest_name in existing:
        raise PasskeyError(
            f"Entry '{dest_name}' already exists. Delete it first or choose a different name."
        )

    if not is_interactive():
        entry = Entry(
            name=dest_name,
            fields=source.fields.copy(),
            config=source.config.copy(),
            policy=source.policy,
        )
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
    final_name = _validate_entry_name(final_name)
    if final_name != dest_name and final_name in existing:
        raise PasskeyError(f"Entry '{final_name}' already exists.")
    entry = Entry(name=final_name, fields=fields, config=config, policy=source.policy)
    save_entry(entry, is_update=False)
    print(f"Cloned '{source.name}' → '{final_name}' with {len(fields)} field(s)")


def cmd_check(
    entry_name: str,
    required_fields: list[str],
    quiet: bool = False,
    *,
    json_output: bool = False,
) -> int:
    """Verify an entry has all required fields.

    Returns:
        0 if all required fields are present, 1 otherwise
        (the CLI layer owns sys.exit).
    """
    entry = _get_entry(entry_name, log_read=False)

    if entry is None:
        remediation = (
            f"Ask the user to run 'passkey new {entry_name}' in their terminal "
            "(never ask them to paste secrets into chat)."
        )
        if json_output:
            print(
                json.dumps(
                    {
                        "entry": entry_name,
                        "exists": False,
                        "valid": False,
                        "present": [],
                        "missing": list(required_fields),
                        "remediation": remediation,
                    },
                    indent=2,
                )
            )
            return 1
        if not quiet:
            print(
                f"MISSING  entry '{entry_name}' not found ({remediation})",
                file=sys.stderr,
            )
        return 1

    all_fields = set(entry.fields) | set(entry.config)
    present = [f for f in required_fields if f in all_fields]
    missing = [f for f in required_fields if f not in all_fields]

    if json_output:
        remediation = (
            f"Ask the user to run 'passkey entry set-field {entry_name} {missing[0]}' "
            "in their terminal."
            if missing
            else None
        )
        print(
            json.dumps(
                {
                    "entry": entry_name,
                    "exists": True,
                    "valid": len(missing) == 0,
                    "present": present,
                    "missing": missing,
                    "remediation": remediation,
                },
                indent=2,
            )
        )
        return 1 if missing else 0

    if not quiet:
        for f in required_fields:
            status = "OK      " if f in all_fields else "MISSING "
            print(f"  {status} {f}")

    if missing:
        if not quiet:
            print(
                f"\n{len(missing)} missing field(s) in '{entry_name}'. "
                f"Ask the user to run 'passkey entry set-field {entry_name} {missing[0]}'.",
                file=sys.stderr,
            )
        return 1

    if not quiet:
        print(f"\nAll {len(required_fields)} field(s) present in '{entry_name}'")
    return 0


def cmd_info(entry: Entry, *, json_output: bool = False) -> None:
    """Show entry details including metadata and field names."""
    if not entry:
        raise PasskeyError("Entry not found")

    from .leases import peek_lease

    lease = peek_lease(entry.name)
    has_lease = lease is not None
    secret_keys = sorted(entry.fields.keys())
    config_keys = sorted(entry.config.keys())

    if json_output:
        payload = {
            "name": entry.name,
            "policy": entry.policy,
            "has_active_lease": has_lease,
            "lease_seconds_remaining": lease["seconds_remaining"] if lease else None,
            "lease_remaining_uses": lease.get("remaining_uses") if lease else None,
            "will_prompt_biometric": entry.policy == "prompt" and not has_lease,
            "fields": secret_keys,
            "config_keys": config_keys,
            "field_count": len(secret_keys),
            "config_count": len(config_keys),
            "created": entry.created,
            "modified": entry.modified,
            "last_rotated": entry.last_rotated,
            "source": entry.source,
        }
        print(json.dumps(payload, indent=2))
        return

    print(f"Entry: {entry.name}")
    print(f"Policy: {entry.policy}")
    if has_lease and lease is not None:
        print(f"Active lease: yes ({lease['seconds_remaining']}s remaining)")
    elif entry.policy == "prompt":
        print("Active lease: no (will prompt Touch ID/OS auth)")
    print(f"Created: {entry.created or 'unknown'}")
    print(f"Modified: {entry.modified or 'unknown'}")
    print(f"Source: {entry.source or 'unknown'}")
    if entry.last_rotated:
        print(f"Last rotated: {entry.last_rotated}")
    print(f"\nFields ({len(secret_keys)}):")
    for key in secret_keys:
        print(f"  {key}")
    if config_keys:
        print(f"\nConfig keys ({len(config_keys)}):")
        for key in config_keys:
            print(f"  {key}")


def cmd_policy(
    entry: Entry,
    policy_value: str | None = None,
    *,
    json_output: bool = False,
) -> None:
    """Show or update an entry's access policy ('allow' or 'prompt')."""
    if not entry:
        raise PasskeyError("Entry not found")

    from .leases import peek_lease

    if policy_value is None:
        if json_output:
            lease = peek_lease(entry.name)
            print(
                json.dumps(
                    {
                        "entry": entry.name,
                        "policy": entry.policy,
                        "has_active_lease": lease is not None,
                        "updated": False,
                    },
                    indent=2,
                )
            )
            return
        print(f"{entry.name}: policy = {entry.policy}")
        return

    normalized = policy_value.strip().lower()
    if normalized not in VALID_POLICIES:
        raise PasskeyError(
            f"Invalid policy '{policy_value}'. Expected one of: {', '.join(sorted(VALID_POLICIES))}"
        )

    entry.policy = normalized
    save_entry(entry, is_update=True)
    log_operation("policy", entry.name, details={"policy": normalized})
    if json_output:
        lease = peek_lease(entry.name)
        print(
            json.dumps(
                {
                    "entry": entry.name,
                    "policy": normalized,
                    "has_active_lease": lease is not None,
                    "updated": True,
                },
                indent=2,
            )
        )
        return
    print(f"Set policy for '{entry.name}' to '{normalized}'")


def cmd_export(file_path: str, entries: list[str] | None = None, no_secrets: bool = False) -> None:
    """Export entries to JSON file."""
    if file_path == "-" and not no_secrets and not sys.stdin.isatty():
        raise PasskeyError(
            "Plaintext export to stdout requires an interactive terminal (TTY). "
            "Use a file path, --encrypt, or --no-secrets instead."
        )

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
            if not sys.stdin.isatty():
                raise PasskeyError(
                    "Plaintext export to stdout requires an interactive terminal (TTY). "
                    "Use a file path, --encrypt, or --no-secrets instead."
                )
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
                print(
                    "Warning: Export contains secrets. File permissions set to 600 (owner only)."
                )
        except FileExistsError:
            raise PasskeyError(
                f"File already exists at '{path}'. Please remove it first."
            ) from None
        except OSError as e:
            raise PasskeyError(f"Error writing to file: {e}") from e

    log_operation("export", details={"count": len(all_entries), "no_secrets": no_secrets})


def cmd_inject(
    in_file: str,
    out_file: str | None = None,
    *,
    to_stdout: bool = False,
    force: bool = False,
    force_git_exposed: bool = False,
) -> None:
    """Resolve {{ passkey://entry/field }} placeholders from in_file into out_file (0o600)."""
    from .leases import authorize_entry_access
    from .mcp_config import is_file_exposed_in_git
    from .references import render_template

    src = Path(in_file).expanduser()
    if not src.exists() or not src.is_file():
        raise PasskeyError(f"Template file not found: '{src}'")

    if out_file is not None and out_file != "-":
        dest_check = Path(out_file).expanduser()
        if not force_git_exposed and is_file_exposed_in_git(dest_check):
            raise PasskeyError(
                f"Refusing to inject secrets into '{dest_check}' because it is inside a git "
                f"repository and NOT gitignored. Add '{dest_check.name}' to .gitignore first, "
                "or pass --force-git-exposed to override."
            )

    template_text = src.read_text(encoding="utf-8")
    rendered = render_template(template_text, authorize_fn=authorize_entry_access)

    if out_file is None or out_file == "-":
        if not to_stdout:
            raise PasskeyError(
                "Refusing to write resolved secrets to stdout without --stdout. "
                "Specify -o <outfile> or pass --stdout in an interactive terminal."
            )
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise PasskeyError(
                "Writing resolved secrets with --stdout requires an interactive terminal (TTY)."
            )
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        log_operation("inject", details={"mode": "stdout"})
        return

    dest = Path(out_file).expanduser()
    dest.parent.mkdir(parents=True, exist_ok=True)

    if dest.exists() and not force:
        raise PasskeyError(
            f"Output file '{dest}' already exists. Pass --force to overwrite atomically."
        )

    fd, tmp_path = tempfile.mkstemp(
        dir=dest.parent,
        prefix=".passkey-inject-",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(rendered)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise

    print(f"Injected secrets into {dest} (permissions 0600)")
    log_operation("inject", details={"mode": "file"})


def cmd_audit(
    limit: int = 20,
    clear: bool = False,
    verify: bool = False,
    *,
    yes: bool = False,
    json_output: bool = False,
) -> int:
    """View, verify, or clear audit log."""
    if verify:
        result = verify_audit_log()
        if json_output:
            print(json.dumps(result, indent=2))
            return 0 if result["valid"] else 1
        if not result["valid"]:
            raise PasskeyError(f"Audit log verification FAILED: {result['error']}")
        print(f"Audit log verified OK ({result['checked']} record(s) intact)")
        return 0

    if clear:
        if not yes:
            confirm = input("Clear audit log? [y/N]: ").strip().lower()
            if confirm != "y":
                print("Cancelled")
                return 0
        if not clear_logs():
            raise PasskeyError("Failed to clear audit log")
        if json_output:
            print(json.dumps({"cleared": True}, indent=2))
        else:
            print("Audit log cleared")
        return 0

    if json_output:
        from .audit import get_sanitized_recent_logs

        print(json.dumps(get_sanitized_recent_logs(limit=limit), indent=2))
        return 0

    logs = get_recent_logs(limit)
    if not logs:
        print("No audit log entries")
        return 0

    print(f"Recent operations (last {len(logs)}):\n")
    for log in logs:
        ts = log.get("timestamp", "")[:19].replace("T", " ")
        op = log.get("operation", "?")
        entry = log.get("entry", "")
        success = "OK" if log.get("success", True) else "FAIL"
        actor = log.get("actor")
        actor_str = ""
        if isinstance(actor, dict):
            actor_str = f" [{actor.get('type', '?')}:{actor.get('client', '?')}]"
        details_str = ", ".join(
            f"{k}={v}" for k, v in log.get("details", {}).items() if k != "error"
        )
        line = f"[{ts}] {op.upper():8s} {success:4s} {entry}{actor_str}"
        if details_str:
            line += f" ({details_str})"
        print(line)
    return 0
