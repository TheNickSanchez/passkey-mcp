"""Tests for the health module."""


from passkey.health import STALE_DAYS
from passkey.models import Entry


class TestEntryRotation:
    def test_rotate_sets_last_rotated(self):
        entry = Entry(name="test", fields={"KEY": "value"})
        assert entry.last_rotated is None
        entry.rotate()
        assert entry.last_rotated is not None

    def test_rotate_updates_modified(self):
        entry = Entry(name="test", fields={"KEY": "value"})
        old_modified = entry.modified
        entry.rotate()
        assert entry.modified != old_modified

    def test_rotation_serialization_roundtrip(self):
        entry = Entry(name="test", fields={"KEY": "value"})
        entry.rotate()
        json_str = entry.to_json()
        restored = Entry.from_json("test", json_str)
        assert restored.last_rotated == entry.last_rotated

    def test_rotation_in_export_dict(self):
        entry = Entry(name="test", fields={"KEY": "value"})
        entry.rotate()
        export = entry.to_export_dict()
        assert "last_rotated" in export
        assert export["last_rotated"] == entry.last_rotated

    def test_no_rotation_not_in_export(self):
        entry = Entry(name="test", fields={"KEY": "value"})
        export = entry.to_export_dict()
        assert "last_rotated" not in export


class TestStaleDays:
    def test_stale_days_constant(self):
        assert STALE_DAYS == 90
