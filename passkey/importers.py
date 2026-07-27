"""Import functions for passkey."""

import csv
import json
import stat
import sys
from pathlib import Path
from urllib.parse import urlparse

from .audit import log_operation
from .keychain import PasskeyError, get_entry, save_entry
from .models import Entry


def _check_file_permissions(path: Path, allow_insecure: bool = False) -> None:
    """Check file permissions and refuse insecure files unless overridden."""
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            if allow_insecure:
                print(
                    f"WARNING: '{path}' has insecure permissions ({oct(mode & 0o777)}).",
                    file=sys.stderr,
                )
                print("  Proceeding anyway due to --insecure flag.", file=sys.stderr)
                print()
            else:
                print(
                    f"ERROR: '{path}' has insecure permissions ({oct(mode & 0o777)}).",
                    file=sys.stderr,
                )
                print("  This file may be readable by other users on this system.", file=sys.stderr)
                print(f"  Fix with: chmod 600 '{path}'", file=sys.stderr)
                print("  Or use --insecure to import anyway.", file=sys.stderr)
                sys.exit(1)
    except Exception:
        pass


def _handle_existing(
    name: str, new_fields: dict[str, str], mode: str, source: str, dry_run: bool = False
) -> tuple[bool, str]:
    """Handle importing when entry already exists.

    Args:
        name: Entry name
        new_fields: Fields to import
        mode: skip, overwrite, or merge
        source: Source identifier for audit
        dry_run: If True, don't actually save

    Returns:
        Tuple of (was_processed, status_message)
    """
    existing = get_entry(name)

    if not existing:
        # New entry
        if not dry_run:
            entry = Entry(name=name, fields=new_fields, source=source)
            save_entry(entry)
        return True, "created"

    # Entry exists - handle based on mode
    if mode == "skip":
        return False, "skipped (exists)"

    elif mode == "overwrite":
        if not dry_run:
            entry = Entry(
                name=name,
                fields=new_fields,
                created=existing.created,  # Preserve original created
                source=source,
            )
            save_entry(entry)
        return True, "overwritten"

    elif mode == "merge":
        if not dry_run:
            changed = existing.merge_fields(new_fields)
            existing.source = f"{existing.source}+{source}"
            save_entry(existing)
        else:
            # For dry run, calculate what would change
            changed = [
                k
                for k in new_fields
                if k not in existing.fields or existing.fields[k] != new_fields[k]
            ]
        if changed:
            return True, f"merged ({len(changed)} fields)"
        return False, "skipped (no changes)"

    return False, "unknown mode"


def import_passkey(
    file_path: str, mode: str = "skip", dry_run: bool = False, allow_insecure: bool = False
) -> None:
    """Import entries from passkey export file.

    Args:
        file_path: Path to passkey export JSON file
        mode: How to handle existing entries (skip, overwrite, merge)
        dry_run: If True, show what would be imported without saving
        allow_insecure: If True, allow importing from world-readable files
    """
    path = Path(file_path).expanduser()

    if not path.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    _check_file_permissions(path, allow_insecure=allow_insecure)

    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    if "entries" not in data:
        print("Error: Invalid passkey export file (missing 'entries')", file=sys.stderr)
        sys.exit(1)

    entries = data["entries"]
    if not entries:
        print("No entries in export file")
        return

    print(f"Found {len(entries)} entry(s) in export file\n")

    if dry_run:
        print("[Dry run mode]\n")

    created = 0
    updated = 0
    skipped = 0

    for entry_data in entries:
        name = entry_data.get("name")
        fields = entry_data.get("fields", {})

        if not name or not fields:
            continue

        # Skip if fields are masked
        if all(v == "***" for v in fields.values()):
            print(f"  {name}: skipped (no secrets in export)")
            skipped += 1
            continue

        processed, status = _handle_existing(name, fields, mode, "import", dry_run)

        print(f"  {name}: {status}")

        if processed:
            if "created" in status:
                created += 1
            else:
                updated += 1
        else:
            skipped += 1

    print(f"\nImported: {created} created, {updated} updated, {skipped} skipped")

    if not dry_run:
        log_operation(
            "import", details={"source": "passkey", "created": created, "updated": updated}
        )


def import_mcp(file_path: str, mode: str = "skip", dry_run: bool = False) -> None:
    """Import secrets from MCP config file.

    Args:
        file_path: Path to MCP config file
        mode: How to handle existing entries (skip, overwrite, merge)
        dry_run: If True, show what would be imported without saving
    """
    path = Path(file_path).expanduser()

    if not path.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path) as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Find servers with env vars
    servers = config.get("mcpServers", config.get("servers", {}))

    if not servers:
        print("No servers found in config file.")
        print("Expected 'mcpServers' or 'servers' key with server definitions.")
        return

    # Collect servers with env vars
    to_import: dict[str, dict[str, str]] = {}

    for name, server_config in servers.items():
        if isinstance(server_config, dict):
            env = server_config.get("env", {})
            if env and isinstance(env, dict):
                secrets = {k: v for k, v in env.items() if v and isinstance(v, str)}
                if secrets:
                    to_import[name] = secrets

    if not to_import:
        print("No environment variables found in any server configuration.")
        return

    print(f"Found {len(to_import)} server(s) with environment variables:\n")

    for name, fields in to_import.items():
        field_names = ", ".join(fields.keys())
        print(f"  {name}: {field_names}")

    print()

    if dry_run:
        print("[Dry run - no changes made]")
        return

    confirm = input(f"Import with mode '{mode}'? [Y/n]: ").strip().lower()
    if confirm not in ("", "y", "yes"):
        print("Cancelled.")
        return

    print()

    created = 0
    updated = 0
    skipped = 0

    for name, fields in to_import.items():
        try:
            processed, status = _handle_existing(name, fields, mode, "import-mcp", dry_run=False)
            print(f"  {name}: {status}")

            if processed:
                if "created" in status:
                    created += 1
                else:
                    updated += 1
            else:
                skipped += 1
        except PasskeyError as e:
            print(f"  {name}: error - {e}", file=sys.stderr)

    print(f"\nImported: {created} created, {updated} updated, {skipped} skipped")

    if created > 0 or updated > 0:
        print("\nUpdate your MCP config to use passkey. Example:")
        example_name = next(iter(to_import.keys()))
        print(f'''
  "{example_name}": {{
    "command": "passkey",
    "args": ["run", "{example_name}", "--", "original-command", "args..."]
  }}
''')

    log_operation("import", details={"source": "mcp", "created": created, "updated": updated})


def import_chrome(
    file_path: str,
    filter_domain: str | None = None,
    mode: str = "skip",
    dry_run: bool = False,
    allow_insecure: bool = False,
) -> None:
    """Import passwords from Chrome CSV export.

    Args:
        file_path: Path to Chrome passwords CSV
        filter_domain: Only import entries matching this domain
        mode: How to handle existing entries (skip, overwrite, merge)
        dry_run: If True, show what would be imported without saving
        allow_insecure: If True, allow importing from world-readable files
    """
    path = Path(file_path).expanduser()

    if not path.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    _check_file_permissions(path, allow_insecure=allow_insecure)

    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except Exception as e:
        print(f"Error reading CSV: {e}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print("No entries found in CSV file.")
        return

    # Check for expected columns
    expected = {"name", "url", "username", "password"}
    if rows and not expected.issubset(set(rows[0].keys())):
        print(f"Error: CSV must have columns: {', '.join(expected)}", file=sys.stderr)
        print(f"Found columns: {', '.join(rows[0].keys())}", file=sys.stderr)
        sys.exit(1)

    # Group by domain/name
    to_import: dict[str, dict[str, str]] = {}

    for row in rows:
        url = row.get("url", "")
        name = row.get("name", "")
        username = row.get("username", "")
        password = row.get("password", "")

        if not password:
            continue

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
        except Exception:
            domain = name.lower().replace(" ", "-") if name else "unknown"

        if filter_domain and filter_domain.lower() not in domain:
            continue

        entry_name = domain.replace(".", "-") if domain else name.lower().replace(" ", "-")

        if not entry_name:
            continue

        if entry_name not in to_import:
            to_import[entry_name] = {}

        fields = to_import[entry_name]

        if username:
            if "USERNAME" not in fields:
                fields["USERNAME"] = username
            elif fields["USERNAME"] != username:
                i = 2
                while f"USERNAME_{i}" in fields:
                    i += 1
                fields[f"USERNAME_{i}"] = username

        if "PASSWORD" not in fields:
            fields["PASSWORD"] = password
        elif fields["PASSWORD"] != password:
            i = 2
            while f"PASSWORD_{i}" in fields:
                i += 1
            fields[f"PASSWORD_{i}"] = password

    if not to_import:
        if filter_domain:
            print(f"No entries found matching '{filter_domain}'")
        else:
            print("No valid entries found in CSV.")
        return

    print(f"Found {len(to_import)} unique site(s):\n")

    for name in sorted(to_import.keys())[:20]:
        fields = to_import[name]
        print(f"  {name}: {len(fields)} field(s)")

    if len(to_import) > 20:
        print(f"  ... and {len(to_import) - 20} more")

    print()

    if dry_run:
        print("[Dry run - no changes made]")
        return

    confirm = input(f"Import {len(to_import)} entries with mode '{mode}'? [Y/n]: ").strip().lower()
    if confirm not in ("", "y", "yes"):
        print("Cancelled.")
        return

    print()

    created = 0
    updated = 0
    skipped = 0

    for name, fields in sorted(to_import.items()):
        try:
            processed, status = _handle_existing(name, fields, mode, "import-chrome", dry_run=False)

            if processed:
                if "created" in status:
                    created += 1
                else:
                    updated += 1
            else:
                skipped += 1
        except PasskeyError as e:
            print(f"  Error saving '{name}': {e}", file=sys.stderr)

    print(f"Imported: {created} created, {updated} updated, {skipped} skipped")

    if created > 0 or updated > 0:
        print("\nUse 'passkey list' to see all entries")
        print("Use 'passkey info <name>' to see fields in an entry")

    log_operation("import", details={"source": "chrome", "created": created, "updated": updated})


def _is_chrome_csv(content: str) -> bool:
    """Check if content looks like a Chrome passwords CSV export.

    Args:
        content: File content to check

    Returns:
        True if content appears to be Chrome CSV format
    """
    lines = content.strip().split("\n")
    if not lines:
        return False

    # Check header row for expected columns
    header = lines[0].lower()
    expected_columns = ["name", "url", "username", "password"]
    return all(col in header for col in expected_columns)


def detect_format(file_path: Path) -> str:
    """Auto-detect import file format.

    Args:
        file_path: Path to the file to detect

    Returns:
        Format string: "passkey", "mcp", or "chrome"

    Raises:
        ValueError: If format cannot be detected
    """
    content = file_path.read_text()

    # Try JSON first
    try:
        data = json.loads(content)
        if "entries" in data:
            return "passkey"
        if "mcpServers" in data or "servers" in data:
            return "mcp"
    except json.JSONDecodeError:
        pass

    # Try CSV (chrome format)
    if _is_chrome_csv(content):
        return "chrome"

    raise ValueError(
        "Unknown file format. Supported formats:\n"
        "  - Passkey export (JSON with 'entries' key)\n"
        "  - MCP config (JSON with 'mcpServers' key)\n"
        "  - Chrome passwords CSV"
    )


def import_auto(
    file_path: str,
    mode: str = "skip",
    dry_run: bool = False,
    filter_domain: str | None = None,
    allow_insecure: bool = False,
) -> None:
    """Unified import with auto-detection.

    Automatically detects the file format and calls the appropriate
    import function.

    Args:
        file_path: Path to the file to import
        mode: How to handle existing entries (skip, overwrite, merge)
        dry_run: If True, show what would be imported without saving
        filter_domain: For Chrome imports, only import entries matching domain
        allow_insecure: If True, allow importing from world-readable files
    """
    path = Path(file_path).expanduser()

    if not path.exists():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        format_type = detect_format(path)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Detected format: {format_type}\n")

    if format_type == "passkey":
        import_passkey(str(path), mode=mode, dry_run=dry_run, allow_insecure=allow_insecure)
    elif format_type == "mcp":
        import_mcp(str(path), mode=mode, dry_run=dry_run)
    elif format_type == "chrome":
        import_chrome(
            str(path),
            filter_domain=filter_domain,
            mode=mode,
            dry_run=dry_run,
            allow_insecure=allow_insecure,
        )
