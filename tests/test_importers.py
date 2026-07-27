"""Tests for passkey.importers module."""

import json
from unittest.mock import patch

import pytest

from passkey.importers import (
    _check_file_permissions,
    detect_format,
    import_passkey,
)


class TestDetectFormat:
    def test_detects_passkey_format(self, tmp_path):
        f = tmp_path / "export.json"
        f.write_text(json.dumps({"entries": [{"name": "test", "fields": {}}]}))
        assert detect_format(f) == "passkey"

    def test_detects_mcp_format(self, tmp_path):
        f = tmp_path / "config.json"
        f.write_text(json.dumps({"mcpServers": {"test": {"command": "node"}}}))
        assert detect_format(f) == "mcp"

    def test_detects_mcp_servers_key(self, tmp_path):
        f = tmp_path / "config.json"
        f.write_text(json.dumps({"servers": {"test": {"command": "node"}}}))
        assert detect_format(f) == "mcp"

    def test_detects_chrome_csv(self, tmp_path):
        f = tmp_path / "passwords.csv"
        f.write_text("name,url,username,password\nTest,https://example.com,user,pass\n")
        assert detect_format(f) == "chrome"

    def test_raises_for_unknown_format(self, tmp_path):
        f = tmp_path / "random.txt"
        f.write_text("just some random text content\n")
        with pytest.raises(ValueError, match="Unknown file format"):
            detect_format(f)


class TestCheckFilePermissions:
    def test_passes_for_secure_file(self, tmp_path):
        f = tmp_path / "secure.json"
        f.write_text("{}")
        f.chmod(0o600)
        _check_file_permissions(f, allow_insecure=False)

    def test_exits_for_insecure_file(self, tmp_path):
        f = tmp_path / "insecure.json"
        f.write_text("{}")
        f.chmod(0o644)
        with pytest.raises(SystemExit):
            _check_file_permissions(f, allow_insecure=False)

    def test_allows_insecure_with_flag(self, tmp_path, capsys):
        f = tmp_path / "insecure.json"
        f.write_text("{}")
        f.chmod(0o644)
        _check_file_permissions(f, allow_insecure=True)
        captured = capsys.readouterr()
        assert "insecure" in captured.err.lower()


class TestImportPasskey:
    @patch("passkey.importers.save_entry")
    @patch("passkey.importers.get_entry")
    def test_imports_new_entries(self, mock_get, mock_save, tmp_path):
        f = tmp_path / "export.json"
        f.chmod(0o600) if f.exists() else None
        data = {
            "entries": [
                {"name": "test-import", "fields": {"TOKEN": "abc123"}}
            ]
        }
        f.write_text(json.dumps(data))
        f.chmod(0o600)

        mock_get.return_value = None
        import_passkey(str(f), mode="skip", allow_insecure=True)
        mock_save.assert_called_once()

    @patch("passkey.importers.get_entry")
    def test_skips_existing_in_skip_mode(self, mock_get, tmp_path):
        f = tmp_path / "export.json"
        data = {
            "entries": [
                {"name": "existing", "fields": {"TOKEN": "abc"}}
            ]
        }
        f.write_text(json.dumps(data))
        f.chmod(0o600)

        from passkey.models import Entry
        mock_get.return_value = Entry(name="existing", fields={"OLD": "val"})
        import_passkey(str(f), mode="skip", allow_insecure=True)

    @patch("passkey.importers.save_entry")
    @patch("passkey.importers.get_entry")
    def test_skips_masked_entries(self, mock_get, mock_save, tmp_path):
        f = tmp_path / "export.json"
        data = {
            "entries": [
                {"name": "masked", "fields": {"TOKEN": "***", "KEY": "***"}}
            ]
        }
        f.write_text(json.dumps(data))
        f.chmod(0o600)

        mock_get.return_value = None
        import_passkey(str(f), mode="skip", allow_insecure=True)
        mock_save.assert_not_called()
