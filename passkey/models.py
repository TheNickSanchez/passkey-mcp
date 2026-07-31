"""Data models for passkey entries."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime

ENTRY_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
RESERVED_NAMES = frozenset({"__entries__"})


def is_valid_name(name) -> bool:
    """Return True if name is a valid, non-reserved entry name.

    Use this to validate untrusted names (imports, bundles) before
    constructing an Entry, which raises ValueError on bad names.
    """
    return (
        isinstance(name, str)
        and name not in RESERVED_NAMES
        and bool(ENTRY_NAME_PATTERN.match(name))
    )


@dataclass
class Entry:
    """A named entry containing secret fields and config fields.

    Attributes:
        name: The entry identifier (e.g., "slack", "jamf")
        fields: Dictionary mapping field names to SECRET values (tokens, passwords, keys)
        config: Dictionary mapping field names to CONFIG values (URLs, hostnames, non-sensitive)
        created: ISO timestamp when entry was created
        modified: ISO timestamp when entry was last modified
        source: How the entry was created (manual, import-mcp, import-chrome)
        last_rotated: ISO timestamp when entry was last rotated
    """

    name: str
    fields: dict[str, str]
    config: dict[str, str] = field(default_factory=dict)
    created: str | None = None
    modified: str | None = None
    source: str | None = None
    last_rotated: str | None = None

    def __post_init__(self):
        """Validate entry name and set timestamps."""
        if self.name in RESERVED_NAMES:
            raise ValueError(f"'{self.name}' is a reserved name")
        if not ENTRY_NAME_PATTERN.match(self.name):
            raise ValueError(
                f"Invalid entry name '{self.name}'. "
                "Names must be 1-64 chars: letters, digits, hyphens, underscores, dots. "
                "Must start with a letter or digit."
            )
        now = datetime.now().isoformat()
        if self.created is None:
            self.created = now
        if self.modified is None:
            self.modified = now
        if self.source is None:
            self.source = "manual"

    def touch(self) -> None:
        """Update the modified timestamp."""
        self.modified = datetime.now().isoformat()

    def to_json(self) -> str:
        """Serialize entry to JSON string for Keychain storage."""
        data = {
            "_meta": {
                "created": self.created,
                "modified": self.modified,
                "source": self.source,
            },
            "fields": self.fields,
            "config": self.config,
        }
        if self.last_rotated:
            data["_meta"]["last_rotated"] = self.last_rotated
        return json.dumps(data)

    def to_export_dict(self, no_secrets: bool = False) -> dict:
        """Convert entry to dictionary for export."""
        result = {
            "name": self.name,
            "fields": {} if no_secrets else self.fields,
            "config": self.config,
            "created": self.created,
            "modified": self.modified,
            "source": self.source,
        }
        if self.last_rotated:
            result["last_rotated"] = self.last_rotated
        return result

    @classmethod
    def from_json(cls, name: str, data: str) -> "Entry":
        """Create Entry from name and JSON string.

        Handles legacy format (just fields), v1 format (with _meta),
        and v2 format (with _meta, fields, and config).

        Args:
            name: The entry identifier
            data: JSON string containing field data

        Returns:
            New Entry instance with parsed fields and metadata
        """
        parsed = json.loads(data)

        # Check if new format with _meta
        if isinstance(parsed, dict) and "_meta" in parsed:
            meta = parsed["_meta"]
            return cls(
                name=name,
                fields=parsed.get("fields", {}),
                config=parsed.get("config", {}),  # Defaults to empty for v1 entries
                created=meta.get("created"),
                modified=meta.get("modified"),
                source=meta.get("source"),
                last_rotated=meta.get("last_rotated"),
            )
        else:
            # Legacy format - just fields dict
            return cls(name=name, fields=parsed, config={})

    def merge_fields(self, other_fields: dict[str, str]) -> list[str]:
        """Merge fields from another dict, returning list of new/updated keys.

        Args:
            other_fields: Fields to merge in

        Returns:
            List of field names that were added or updated
        """
        changed = []
        for key, value in other_fields.items():
            if key not in self.fields or self.fields[key] != value:
                changed.append(key)
            self.fields[key] = value
        if changed:
            self.touch()
        return changed

    def get_all_env_vars(self) -> dict[str, str]:
        """Get all fields (secrets + config) as a single dict for env injection.

        Config values are added first, then secrets override if same key exists.

        Returns:
            Combined dictionary of all environment variables
        """
        combined = {}
        combined.update(self.config)  # Config first
        combined.update(self.fields)  # Secrets override if same key
        return combined

    def add_config(self, key: str, value: str) -> None:
        """Add a config (non-secret) field.

        Args:
            key: The config field name
            value: The config value
        """
        self.config[key] = value
        self.touch()

    def move_to_config(self, key: str) -> bool:
        """Move a field from secrets to config.

        Args:
            key: The field name to move

        Returns:
            True if field was moved, False if field didn't exist in secrets
        """
        if key in self.fields:
            self.config[key] = self.fields.pop(key)
            self.touch()
            return True
        return False

    def rotate(self) -> None:
        """Mark entry as rotated by updating the last_rotated timestamp."""
        self.last_rotated = datetime.now().isoformat()
        self.touch()
