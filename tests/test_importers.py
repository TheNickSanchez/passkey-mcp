"""Tests for passkey.importers module."""

import csv
import json
from unittest.mock import patch

import pytest

from passkey.importers import (
    _check_file_permissions,
    _is_chrome_csv,
    detect_format,
    import_chrome,
    import_mcp,
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

    def test_exits_for_missing_file(self):
        with pytest.raises(SystemExit):
            import_passkey("/nonexistent/file.json")

    def test_exits_for_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        with pytest.raises(SystemExit):
            import_passkey(str(f))

    def test_exits_for_missing_entries_key(self, tmp_path):
        f = tmp_path / "noentries.json"
        f.write_text(json.dumps({"other": "data"}))
        with pytest.raises(SystemExit):
            import_passkey(str(f))

    def test_empty_entries(self, tmp_path, capsys):
        f = tmp_path / "empty.json"
        f.write_text(json.dumps({"entries": []}))
        import_passkey(str(f), allow_insecure=True)
        captured = capsys.readouterr()
        assert "No entries" in captured.out


class TestIsChromeCsv:
    def test_valid_chrome_csv(self):
        assert _is_chrome_csv("name,url,username,password\nfoo,http://x.com,u,p\n") is True

    def test_invalid_chrome_csv(self):
        assert _is_chrome_csv("col1,col2,col3\na,b,c\n") is False

    def test_empty_content(self):
        assert _is_chrome_csv("") is False

    def test_partial_columns(self):
        assert _is_chrome_csv("name,url\nfoo,http://x.com\n") is False


class TestImportMcp:
    @patch("passkey.importers.save_entry")
    @patch("passkey.importers.get_entry")
    def test_imports_mcp_env_vars(self, mock_get, mock_save, tmp_path):
        f = tmp_path / "mcp.json"
        config = {
            "mcpServers": {
                "my-server": {
                    "command": "node",
                    "env": {"API_KEY": "secret123", "TOKEN": "tok456"}
                }
            }
        }
        f.write_text(json.dumps(config))
        mock_get.return_value = None
        import_mcp(str(f), mode="skip", dry_run=True)
        mock_save.assert_not_called()

    @patch("passkey.importers.save_entry")
    @patch("passkey.importers.get_entry")
    def test_imports_servers_key(self, mock_get, mock_save, tmp_path):
        f = tmp_path / "mcp.json"
        config = {
            "servers": {
                "svc": {"env": {"KEY": "val"}}
            }
        }
        f.write_text(json.dumps(config))
        mock_get.return_value = None
        import_mcp(str(f), mode="skip", dry_run=True)
        mock_save.assert_not_called()

    def test_exits_for_missing_file(self):
        with pytest.raises(SystemExit):
            import_mcp("/nonexistent/mcp.json")

    def test_exits_for_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        with pytest.raises(SystemExit):
            import_mcp(str(f))

    def test_no_servers_found(self, tmp_path, capsys):
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps({"other": "data"}))
        import_mcp(str(f), dry_run=True)
        captured = capsys.readouterr()
        assert "No servers found" in captured.out

    def test_no_env_vars(self, tmp_path, capsys):
        f = tmp_path / "mcp.json"
        config = {"mcpServers": {"svc": {"command": "node"}}}
        f.write_text(json.dumps(config))
        import_mcp(str(f), dry_run=True)
        captured = capsys.readouterr()
        assert "No environment variables" in captured.out


class TestImportChrome:
    @patch("passkey.importers.save_entry")
    @patch("passkey.importers.get_entry")
    def test_dry_run_shows_entries(self, mock_get, mock_save, tmp_path, capsys):
        f = tmp_path / "chrome.csv"
        with open(f, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["name", "url", "username", "password"])
            writer.writerow(["Test", "https://example.com", "user", "pass123"])
        f.chmod(0o600)
        mock_get.return_value = None
        import_chrome(str(f), mode="skip", dry_run=True, allow_insecure=True)
        mock_save.assert_not_called()
        captured = capsys.readouterr()
        assert "1 unique site" in captured.out

    @patch("passkey.importers.save_entry")
    @patch("passkey.importers.get_entry")
    def test_filter_domain(self, mock_get, mock_save, tmp_path, capsys):
        f = tmp_path / "chrome.csv"
        with open(f, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["name", "url", "username", "password"])
            writer.writerow(["Site1", "https://example.com", "u1", "p1"])
            writer.writerow(["Site2", "https://other.com", "u2", "p2"])
        f.chmod(0o600)
        mock_get.return_value = None
        import_chrome(str(f), filter_domain="example", mode="skip", dry_run=True, allow_insecure=True)
        captured = capsys.readouterr()
        assert "1 unique site" in captured.out

    def test_exits_for_missing_file(self):
        with pytest.raises(SystemExit):
            import_chrome("/nonexistent/chrome.csv")

    def test_exits_for_bad_columns(self, tmp_path):
        f = tmp_path / "bad.csv"
        with open(f, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["col1", "col2", "col3"])
            writer.writerow(["a", "b", "c"])
        with pytest.raises(SystemExit):
            import_chrome(str(f))

    def test_empty_csv(self, tmp_path, capsys):
        f = tmp_path / "empty.csv"
        with open(f, "w", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["name", "url", "username", "password"])
        import_chrome(str(f), allow_insecure=True)
        captured = capsys.readouterr()
        assert "No entries found" in captured.out
