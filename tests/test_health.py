"""Tests for the health module."""

import json
from datetime import datetime, timedelta

from passkey.doctor import STALE_DAYS
from passkey.health import cmd_audit_summary
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


def _write_audit_log(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))


class TestAuditSummary:
    """Regression: summary claimed 'last 30 days' but never filtered."""

    def test_filters_to_last_30_days(self, isolated_data_dir, capsys):
        from unittest.mock import patch

        from passkey.audit import get_log_path

        old_ts = (datetime.now() - timedelta(days=40)).isoformat()
        new_ts = datetime.now().isoformat()
        _write_audit_log(get_log_path(), [
            {"timestamp": old_ts, "operation": "create", "entry": "old-entry", "success": True},
            {"timestamp": new_ts, "operation": "read", "entry": "new-entry", "success": True},
        ])

        # Keep the oldest-entry lookup off the real keychain
        with patch("passkey.health.get_all_entries", return_value=[]):
            cmd_audit_summary()
        out = capsys.readouterr().out

        assert "last 30 days" in out
        assert "read" in out
        # The 40-day-old create must be filtered out of the op counts
        assert "create " not in out
        assert "old-entry" not in out

    def test_empty_window_message(self, isolated_data_dir, capsys):
        from passkey.audit import get_log_path

        old_ts = (datetime.now() - timedelta(days=90)).isoformat()
        _write_audit_log(get_log_path(), [
            {"timestamp": old_ts, "operation": "create", "entry": "x", "success": True},
        ])

        cmd_audit_summary()
        assert "No audit log entries in the last 30 days" in capsys.readouterr().out

    def test_unparseable_timestamps_skipped(self, isolated_data_dir, capsys):
        from unittest.mock import patch

        from passkey.audit import get_log_path

        _write_audit_log(get_log_path(), [
            {"timestamp": "not-a-date", "operation": "create", "entry": "x", "success": True},
            {"timestamp": datetime.now().isoformat(), "operation": "delete", "entry": "y",
             "success": True},
        ])

        with patch("passkey.health.get_all_entries", return_value=[]):
            cmd_audit_summary()
        out = capsys.readouterr().out
        assert "delete" in out
        assert "create " not in out
