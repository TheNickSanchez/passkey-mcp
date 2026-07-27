"""Tests for passkey.models module."""

import json

from passkey.models import Entry


class TestEntry:
    """Tests for Entry dataclass."""

    def test_create_entry(self):
        """Entry can be created with name and fields."""
        entry = Entry(name="test", fields={"KEY": "value"})
        assert entry.name == "test"
        assert entry.fields == {"KEY": "value"}

    def test_to_json(self):
        """to_json() returns valid JSON string with metadata and fields."""
        entry = Entry(name="test", fields={"A": "1", "B": "2"})
        result = entry.to_json()
        data = json.loads(result)
        assert "fields" in data
        assert data["fields"] == {"A": "1", "B": "2"}
        assert "_meta" in data
        assert "created" in data["_meta"]
        assert "modified" in data["_meta"]
        assert "source" in data["_meta"]

    def test_from_json(self):
        """from_json() creates Entry from name and JSON string."""
        json_str = '{"KEY": "secret"}'
        entry = Entry.from_json("myentry", json_str)
        assert entry.name == "myentry"
        assert entry.fields == {"KEY": "secret"}

    def test_roundtrip(self):
        """Entry survives JSON round-trip."""
        original = Entry(name="test", fields={"TOKEN": "abc123"})
        json_str = original.to_json()
        restored = Entry.from_json(original.name, json_str)
        assert restored.name == original.name
        assert restored.fields == original.fields

    def test_empty_fields(self):
        """Entry can have empty fields dict."""
        entry = Entry(name="empty", fields={})
        data = json.loads(entry.to_json())
        assert data["fields"] == {}

    def test_special_characters(self):
        """Entry handles special characters in values."""
        entry = Entry(name="special", fields={
            "QUOTES": 'value with "quotes"',
            "NEWLINE": "line1\nline2",
            "UNICODE": "emoji"
        })
        json_str = entry.to_json()
        restored = Entry.from_json("special", json_str)
        assert restored.fields == entry.fields

    def test_entry_with_config(self):
        """Entry can have separate config fields."""
        entry = Entry(
            name="jamf",
            fields={"JAMF_TOKEN": "secret123"},
            config={"JAMF_URL": "https://jamf.example.com"}
        )
        assert entry.fields == {"JAMF_TOKEN": "secret123"}
        assert entry.config == {"JAMF_URL": "https://jamf.example.com"}

    def test_entry_json_roundtrip_with_config(self):
        """Entry with config serializes and deserializes correctly."""
        original = Entry(
            name="test",
            fields={"TOKEN": "abc"},
            config={"URL": "https://example.com"}
        )
        json_str = original.to_json()
        restored = Entry.from_json("test", json_str)
        assert restored.fields == original.fields
        assert restored.config == original.config

    def test_entry_backwards_compat_no_config(self):
        """Legacy entries without config load with empty config dict."""
        legacy_json = '{"_meta": {"created": "2026-01-01"}, "fields": {"TOKEN": "x"}}'
        entry = Entry.from_json("legacy", legacy_json)
        assert entry.fields == {"TOKEN": "x"}
        assert entry.config == {}

    def test_entry_backwards_compat_legacy_format(self):
        """Pure legacy entries (no _meta) load with empty config dict."""
        legacy_json = '{"TOKEN": "x", "URL": "https://example.com"}'
        entry = Entry.from_json("legacy", legacy_json)
        assert entry.fields == {"TOKEN": "x", "URL": "https://example.com"}
        assert entry.config == {}

    def test_get_all_env_vars(self):
        """get_all_env_vars combines config and fields."""
        entry = Entry(
            name="test",
            fields={"TOKEN": "secret"},
            config={"URL": "https://example.com"}
        )
        env = entry.get_all_env_vars()
        assert env == {"TOKEN": "secret", "URL": "https://example.com"}

    def test_get_all_env_vars_secrets_override_config(self):
        """Secrets take precedence over config if same key exists."""
        entry = Entry(
            name="test",
            fields={"KEY": "secret_value"},
            config={"KEY": "config_value"}
        )
        env = entry.get_all_env_vars()
        assert env["KEY"] == "secret_value"

    def test_move_to_config(self):
        """move_to_config moves field from secrets to config."""
        entry = Entry(name="test", fields={"URL": "https://example.com", "TOKEN": "abc"})
        assert entry.move_to_config("URL") is True
        assert "URL" not in entry.fields
        assert entry.config["URL"] == "https://example.com"
        assert entry.fields == {"TOKEN": "abc"}

    def test_move_to_config_nonexistent(self):
        """move_to_config returns False for nonexistent field."""
        entry = Entry(name="test", fields={"TOKEN": "abc"})
        assert entry.move_to_config("NONEXISTENT") is False
        assert entry.config == {}

    def test_add_config(self):
        """add_config adds a config field."""
        entry = Entry(name="test", fields={"TOKEN": "abc"})
        entry.add_config("URL", "https://example.com")
        assert entry.config == {"URL": "https://example.com"}

    def test_to_export_dict_includes_config(self):
        """to_export_dict includes config field."""
        entry = Entry(
            name="test",
            fields={"TOKEN": "abc"},
            config={"URL": "https://example.com"}
        )
        exported = entry.to_export_dict()
        assert exported["config"] == {"URL": "https://example.com"}
        assert exported["fields"] == {"TOKEN": "abc"}
