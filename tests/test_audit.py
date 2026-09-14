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


class TestRotation:
    """P3-6: audit log is size-capped by dropping oldest lines."""

    def test_oversized_log_drops_oldest_half(self, tmp_path, monkeypatch):
        import passkey.audit as audit_mod

        log_file = tmp_path / "audit.log"
        # 10 existing records, then force the cap below their total size
        log_file.write_text(
            "".join(json.dumps({"operation": f"op{i}", "timestamp": "2026-01-01"}) + "\n"
                    for i in range(10))
        )
        monkeypatch.setattr(audit_mod, "MAX_LOG_BYTES", 100)

        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            log_operation("new-op", "entry")

        lines = log_file.read_text().strip().split("\n")
        ops = [json.loads(line)["operation"] for line in lines]
        # Oldest half dropped, newest kept, plus the appended record
        assert "op0" not in ops
        assert "op4" not in ops
        assert "op9" in ops
        assert "new-op" in ops

    def test_small_log_untouched(self, tmp_path):
        log_file = tmp_path / "audit.log"
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(log_file)}):
            log_operation("a", "e")
            log_operation("b", "e")
        assert len(log_file.read_text().strip().split("\n")) == 2


class TestSecurityHardening:
    def test_rejects_symlink(self, tmp_path):
        import pytest
        real_file = tmp_path / "real.log"
        real_file.touch()
        symlink_file = tmp_path / "link.log"
        symlink_file.symlink_to(real_file)

        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(symlink_file)}):
            with pytest.raises(ValueError, match="symbolic link"):
                from passkey.audit import get_log_path
                get_log_path()

    def test_rejects_system_directory(self):
        import pytest
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": "/etc/passkey_audit.log"}):
            with pytest.raises(ValueError, match="system directory"):
                from passkey.audit import get_log_path
                get_log_path()

    def test_rejects_shell_file(self):
        import pytest
        from pathlib import Path
        target = Path.home() / ".zshrc"
        with patch.dict(os.environ, {"PASSKEY_AUDIT_LOG": str(target)}):
            with pytest.raises(ValueError, match="shell startup file"):
                from passkey.audit import get_log_path
                get_log_path()

    def test_rotation_does_not_corrupt_non_audit_files(self, tmp_path, monkeypatch):
        import passkey.audit as audit_mod
        fake_db = tmp_path / "data.db"
        fake_db.write_text("BINARY_OR_SQL_NON_JSON_CONTENT\n" * 100)
        original_content = fake_db.read_text()
        monkeypatch.setattr(audit_mod, "MAX_LOG_BYTES", 50)

        audit_mod._rotate_if_needed(fake_db)
        # Content must not be truncated
        assert fake_db.read_text() == original_content
