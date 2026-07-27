"""Tests for passkey.audit module."""

import json
import os
from unittest.mock import patch

from passkey.audit import clear_logs, get_recent_logs, log_operation


class TestLogOperation:
    def test_writes_log_entry(self, tmp_path):
        log_file = tmp_path / "audit.log"
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            log_operation("create", "test-entry", {"field_count": 3})

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["operation"] == "create"
        assert record["entry"] == "test-entry"
        assert record["success"] is True
        assert record["details"]["field_count"] == 3

    def test_logs_failure(self, tmp_path):
        log_file = tmp_path / "audit.log"
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            log_operation("read", "secret", {"error": "denied"}, success=False)

        record = json.loads(log_file.read_text().strip())
        assert record["success"] is False

    def test_creates_directory(self, tmp_path):
        log_file = tmp_path / "subdir" / "audit.log"
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            log_operation("test", "entry")
        assert log_file.exists()

    def test_sets_secure_permissions(self, tmp_path):
        log_file = tmp_path / "audit.log"
        log_file.write_text("")
        log_file.chmod(0o644)
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            log_operation("test", "entry")
        assert log_file.stat().st_mode & 0o777 == 0o600


class TestGetRecentLogs:
    def test_returns_empty_for_missing_file(self, tmp_path):
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(tmp_path / "missing.log")}):
            assert get_recent_logs() == []

    def test_returns_entries_newest_first(self, tmp_path):
        log_file = tmp_path / "audit.log"
        entries = [
            json.dumps({"timestamp": "2026-01-01T00:00:00", "operation": "first"}),
            json.dumps({"timestamp": "2026-01-02T00:00:00", "operation": "second"}),
        ]
        log_file.write_text("\n".join(entries) + "\n")
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            result = get_recent_logs(limit=10)
        assert result[0]["operation"] == "second"
        assert result[1]["operation"] == "first"

    def test_respects_limit(self, tmp_path):
        log_file = tmp_path / "audit.log"
        entries = [json.dumps({"operation": f"op{i}"}) for i in range(20)]
        log_file.write_text("\n".join(entries) + "\n")
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            result = get_recent_logs(limit=5)
        assert len(result) == 5

    def test_skips_corrupted_lines(self, tmp_path):
        log_file = tmp_path / "audit.log"
        log_file.write_text('{"operation": "good"}\nnot json\n{"operation": "also_good"}\n')
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            result = get_recent_logs()
        assert len(result) == 2


class TestClearLogs:
    def test_clears_existing_log(self, tmp_path):
        log_file = tmp_path / "audit.log"
        log_file.write_text("some data\n")
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            assert clear_logs() is True
        assert not log_file.exists()

    def test_returns_true_for_missing_file(self, tmp_path):
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(tmp_path / "missing.log")}):
            assert clear_logs() is True
