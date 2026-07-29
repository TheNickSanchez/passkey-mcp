"""Tests for MCP server tools."""

from unittest.mock import patch

import pytest

from passkey.mcp_config import ADAPTERS
from passkey.mcp_server import (
    passkey_doctor,
    passkey_get_entry_fields,
    passkey_list_entries,
    passkey_setup_server,
    passkey_status,
)
from passkey.models import Entry


class TestPasskeyListEntries:
    """Tests for passkey_list_entries tool."""

    @patch('passkey.mcp_server.list_entries')
    def test_returns_empty_list(self, mock_list):
        mock_list.return_value = []
        result = passkey_list_entries()
        assert result == []

    @patch('passkey.mcp_server.list_entries')
    def test_returns_entry_names(self, mock_list):
        mock_list.return_value = ["slack", "github"]
        result = passkey_list_entries()
        assert result == ["slack", "github"]

    @patch('passkey.mcp_server.list_entries')
    def test_raises_on_keychain_error(self, mock_list):
        from passkey.keychain import PasskeyError
        mock_list.side_effect = PasskeyError("Access denied")
        with pytest.raises(Exception, match="Failed to access keychain"):
            passkey_list_entries()


class TestPasskeyGetEntryFields:
    """Tests for passkey_get_entry_fields tool."""

    @patch('passkey.mcp_server.get_entry')
    def test_returns_field_names(self, mock_get):
        mock_entry = Entry(name="test", fields={"TOKEN": "secret", "KEY": "value"})
        mock_get.return_value = mock_entry
        result = passkey_get_entry_fields("test")
        assert set(result) == {"TOKEN", "KEY"}

    @patch('passkey.mcp_server.get_entry')
    def test_raises_for_missing_entry(self, mock_get):
        mock_get.return_value = None
        with pytest.raises(Exception, match="not found"):
            passkey_get_entry_fields("nonexistent")

    @patch('passkey.mcp_server.get_entry')
    def test_raises_on_keychain_error(self, mock_get):
        from passkey.keychain import PasskeyError
        mock_get.side_effect = PasskeyError("Access denied")
        with pytest.raises(Exception, match="Failed to access keychain"):
            passkey_get_entry_fields("test")


class TestPasskeyStatus:
    """Tests for passkey_status tool."""

    def _make_adapter(self, tmp_path, root_key="mcpServers"):
        """Helper to create a minimal adapter pointing to a tmp_path config."""
        import sys

        from passkey.mcp_config import ToolAdapter
        cfg = tmp_path / "config.json"
        cfg.touch()
        return ToolAdapter(
            name="test", display_name="Test", root_key=root_key,
            global_paths={sys.platform: cfg}, project_paths={},
        )

    @patch('passkey.mcp_server.load_config')
    def test_handles_missing_config(self, mock_load):
        mock_load.side_effect = FileNotFoundError()
        result = passkey_status()
        assert result["servers"] == []
        assert result["summary"]["secured"] == 0

    @patch('passkey.mcp_server.load_config')
    def test_handles_invalid_config(self, mock_load):
        from passkey.mcp_config import MCPConfigError
        mock_load.side_effect = MCPConfigError("Invalid JSON")
        result = passkey_status()
        assert result["servers"] == []
        assert result["summary"]["secured"] == 0

    @patch('passkey.mcp_server.get_mcp_servers')
    @patch('passkey.mcp_server.load_config')
    def test_returns_empty_when_no_servers(self, mock_load, mock_get_servers):
        mock_load.return_value = {}
        mock_get_servers.return_value = {}
        result = passkey_status()
        assert result["servers"] == []

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.load_config')
    def test_detects_secured_server(self, mock_load, mock_list, tmp_path):
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {
            "mcpServers": {
                "myserver": {
                    "command": "passkey",
                    "args": ["run", "myserver", "--", "python", "-m", "server"],
                }
            }
        }
        mock_list.return_value = ["myserver"]
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_status()
        assert len(result["servers"]) == 1
        assert result["servers"][0]["status"] == "secured"
        assert result["summary"]["secured"] == 1

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.load_config')
    def test_detects_exposed_server(self, mock_load, mock_list, tmp_path):
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {
            "mcpServers": {
                "myserver": {
                    "command": "python",
                    "env": {"API_TOKEN": "secret123"},
                }
            }
        }
        mock_list.return_value = []
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_status()
        assert len(result["servers"]) == 1
        assert result["servers"][0]["status"] == "exposed"
        assert result["summary"]["exposed"] == 1

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.load_config')
    def test_detects_partial_server(self, mock_load, mock_list, tmp_path):
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {
            "mcpServers": {
                "myserver": {
                    "command": "passkey",
                    "args": ["run", "myserver", "--", "python"],
                    "env": {"LEFTOVER_TOKEN": "oops"},
                }
            }
        }
        mock_list.return_value = ["myserver"]
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_status()
        assert len(result["servers"]) == 1
        assert result["servers"][0]["status"] == "partial"
        assert result["summary"]["partial"] == 1

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.load_config')
    def test_detects_broken_server(self, mock_load, mock_list, tmp_path):
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {
            "mcpServers": {
                "myserver": {
                    "command": "passkey",
                    "args": ["run", "myserver", "--", "python"],
                }
            }
        }
        mock_list.return_value = []
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_status()
        assert len(result["servers"]) == 1
        assert result["servers"][0]["status"] == "broken"
        # 'broken' isn't counted in the summary dict, but the server is reported

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.load_config')
    def test_detects_no_secrets_server(self, mock_load, mock_list, tmp_path):
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {
            "mcpServers": {
                "myserver": {
                    "command": "python",
                    "env": {"PYTHONPATH": "/lib"},
                }
            }
        }
        mock_list.return_value = []
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_status()
        assert len(result["servers"]) == 1
        assert result["servers"][0]["status"] == "no_secrets"
        assert result["summary"]["no_secrets"] == 1

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.load_config')
    def test_handles_keychain_error_gracefully(self, mock_load, mock_list, tmp_path):
        from passkey.keychain import PasskeyError
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {
            "mcpServers": {
                "myserver": {
                    "command": "python",
                    "env": {"API_TOKEN": "secret"},
                }
            }
        }
        mock_list.side_effect = PasskeyError("Access denied")
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_status()
        # Should still report exposed, not crash
        assert len(result["servers"]) == 1
        assert result["servers"][0]["status"] == "exposed"

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.load_config')
    def test_skips_empty_servers(self, mock_load, mock_list, tmp_path):
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {"mcpServers": {}}
        mock_list.return_value = []
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_status()
        assert result["servers"] == []
        assert all(v == 0 for v in result["summary"].values())

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.load_config')
    def test_multiple_adapters(self, mock_load, mock_list, tmp_path):
        adapter1 = self._make_adapter(tmp_path, root_key="mcpServers")
        adapter2 = self._make_adapter(tmp_path, root_key="servers")
        config = {
            "mcpServers": {"srv1": {"command": "python", "env": {"TOKEN": "x"}}},
            "servers": {"srv2": {"command": "passkey", "args": ["run", "srv2", "--", "node"]}},
        }
        mock_load.return_value = config
        mock_list.return_value = ["srv2"]
        with patch('passkey.mcp_server.ADAPTERS', {"a1": adapter1, "a2": adapter2}):
            result = passkey_status()
        assert len(result["servers"]) == 2
        # Each adapter reads from the same file but uses different root_keys
        statuses = {s["server"]: s["status"] for s in result["servers"]}
        assert statuses["srv1"] == "exposed"
        assert statuses["srv2"] == "secured"


class TestPasskeyWrapServer:
    """Tests for passkey_wrap_server tool (aliased as passkey_setup_server)."""

    @patch('passkey.mcp_server.get_entry')
    def test_handles_missing_entry(self, mock_get):
        mock_get.return_value = None
        result = passkey_setup_server("nonexistent")
        assert result["success"] is False
        assert "not found" in result["message"]

    @patch('passkey.mcp_server.get_entry')
    def test_handles_keychain_error(self, mock_get):
        from passkey.keychain import PasskeyError
        mock_get.side_effect = PasskeyError("Access denied")
        result = passkey_setup_server("test")
        assert result["success"] is False
        assert "keychain" in result["message"].lower()

    @patch('passkey.mcp_server.get_entry')
    def test_handles_no_config_paths(self, mock_get):
        mock_get.return_value = Entry(name="test", fields={"TOKEN": "value"})
        with patch('passkey.mcp_server.ADAPTERS', {}):
            result = passkey_setup_server("test")
        assert result["success"] is False
        assert "No config files" in result["message"]

    @patch('passkey.mcp_server.save_config')
    @patch('passkey.mcp_server.rewrite_server_for_passkey')
    @patch('passkey.mcp_server.is_passkey_wrapped')
    @patch('passkey.mcp_server.get_mcp_servers')
    @patch('passkey.mcp_server.find_adapter_for_path')
    @patch('passkey.mcp_server.load_config')
    @patch('passkey.mcp_server.get_entry')
    def test_skips_already_wrapped(self, mock_get_entry, mock_load, mock_find_adapter,
                                    mock_get_servers, mock_wrapped, mock_rewrite, mock_save, tmp_path):
        config_path = tmp_path / "test.json"
        config_path.write_text('{"mcpServers": {"test": {"command": "passkey"}}}')

        mock_get_entry.return_value = Entry(name="test", fields={"TOKEN": "value"})
        mock_load.return_value = {"mcpServers": {"test": {"command": "passkey"}}}
        mock_find_adapter.return_value = ADAPTERS["claude"]
        mock_get_servers.return_value = {"test": {"command": "passkey"}}
        mock_wrapped.return_value = True

        result = passkey_setup_server("test", config_paths=[str(config_path)])
        assert len(result["configs_skipped"]) == 1
        assert result["configs_skipped"][0]["reason"] == "already wrapped"
        mock_save.assert_not_called()

    @patch('passkey.mcp_server.save_config')
    @patch('passkey.mcp_server.rewrite_server_for_passkey')
    @patch('passkey.mcp_server.is_passkey_wrapped')
    @patch('passkey.mcp_server.get_mcp_servers')
    @patch('passkey.mcp_server.find_adapter_for_path')
    @patch('passkey.mcp_server.load_config')
    @patch('passkey.mcp_server.get_entry')
    def test_updates_config_successfully(self, mock_get_entry, mock_load, mock_find_adapter,
                                          mock_get_servers, mock_wrapped, mock_rewrite, mock_save, tmp_path):
        config_path = tmp_path / "test.json"
        config_path.write_text('{"mcpServers": {"test": {"command": "node"}}}')

        mock_get_entry.return_value = Entry(name="test", fields={"TOKEN": "value"})
        mock_load.return_value = {"mcpServers": {"test": {"command": "node"}}}
        mock_find_adapter.return_value = ADAPTERS["claude"]
        mock_get_servers.return_value = {"test": {"command": "node"}}
        mock_wrapped.return_value = False
        mock_rewrite.return_value = {"command": "passkey", "args": ["run", "test", "--", "node"]}

        result = passkey_setup_server("test", config_paths=[str(config_path)])
        assert result["success"] is True
        assert len(result["configs_updated"]) == 1
        mock_save.assert_called_once()

    @patch('passkey.mcp_server.save_config')
    @patch('passkey.mcp_server.rewrite_server_for_passkey')
    @patch('passkey.mcp_server.is_passkey_wrapped')
    @patch('passkey.mcp_server.get_mcp_servers')
    @patch('passkey.mcp_server.find_adapter_for_path')
    @patch('passkey.mcp_server.load_config')
    @patch('passkey.mcp_server.get_entry')
    def test_auto_detects_all_config_paths(self, mock_get_entry, mock_load, mock_find_adapter,
                                            mock_get_servers, mock_wrapped, mock_rewrite,
                                            mock_save, tmp_path):
        """Test config_paths=None auto-detects all adapter paths."""
        cfg1 = tmp_path / "cfg1.json"
        cfg2 = tmp_path / "cfg2.json"
        cfg1.write_text('{"mcpServers": {"myserver": {"command": "node"}}}')
        cfg2.write_text('{}')

        import sys

        from passkey.mcp_config import ToolAdapter
        adapter1 = ToolAdapter(
            name="t1", display_name="T1", root_key="mcpServers",
            global_paths={sys.platform: cfg1}, project_paths={},
        )
        adapter2 = ToolAdapter(
            name="t2", display_name="T2", root_key="mcpServers",
            global_paths={sys.platform: cfg2}, project_paths={},
        )

        mock_get_entry.return_value = Entry(name="myserver", fields={"TOKEN": "value"})
        mock_find_adapter.side_effect = lambda p: adapter1 if p == cfg1 else adapter2
        mock_get_servers.side_effect = lambda config, _: config.get("mcpServers", {})
        mock_wrapped.return_value = False
        mock_rewrite.return_value = {"command": "passkey", "args": ["run", "myserver", "--", "node"]}
        mock_load.side_effect = [{"mcpServers": {"myserver": {"command": "node"}}}, {}]

        with patch('passkey.mcp_server.ADAPTERS', {"t1": adapter1, "t2": adapter2}):
            result = passkey_setup_server("myserver")

        assert len(result["configs_updated"]) == 1
        assert str(cfg1) in result["configs_updated"]
        mock_save.assert_called_once()

    @patch('passkey.mcp_server.save_config')
    @patch('passkey.mcp_server.rewrite_server_for_passkey')
    @patch('passkey.mcp_server.is_passkey_wrapped')
    @patch('passkey.mcp_server.get_mcp_servers')
    @patch('passkey.mcp_server.find_adapter_for_path')
    @patch('passkey.mcp_server.load_config')
    @patch('passkey.mcp_server.get_entry')
    def test_handles_unknown_adapter_path(self, mock_get_entry, mock_load, mock_find_adapter,
                                           mock_get_servers, mock_wrapped, mock_rewrite,
                                           mock_save, tmp_path):
        config_path = tmp_path / "unknown.json"
        config_path.write_text('{"servers": {"srv": {"command": "node"}}}')

        mock_get_entry.return_value = Entry(name="srv", fields={"TOKEN": "value"})
        mock_load.return_value = {"servers": {"srv": {"command": "node"}}}
        mock_find_adapter.return_value = None  # No adapter found for this path
        result = passkey_setup_server("srv", config_paths=[str(config_path)])
        assert len(result["configs_skipped"]) == 1
        assert result["configs_skipped"][0]["reason"] == "unknown config format"

    @patch('passkey.mcp_server.find_adapter_for_path')
    @patch('passkey.mcp_server.get_entry')
    def test_server_not_found_in_config(self, mock_get, mock_find, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text('{"mcpServers": {"other-server": {"command": "node"}}}')

        mock_get.return_value = Entry(name="myserver", fields={"TOKEN": "value"})
        mock_find.return_value = ADAPTERS["claude"]
        result = passkey_setup_server("myserver", config_paths=[str(config_path)])
        assert len(result["configs_skipped"]) == 1
        assert result["configs_skipped"][0]["reason"] == "server not found"

    @patch('passkey.mcp_server.save_config')
    @patch('passkey.mcp_server.find_adapter_for_path')
    @patch('passkey.mcp_server.get_entry')
    def test_save_error_returns_error(self, mock_get, mock_find, mock_save, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text('{"mcpServers": {"myserver": {"command": "node"}}}')

        mock_get.return_value = Entry(name="myserver", fields={"TOKEN": "value"})
        mock_find.return_value = ADAPTERS["claude"]
        mock_save.side_effect = PermissionError("Permission denied")
        result = passkey_setup_server("myserver", config_paths=[str(config_path)])
        assert result["success"] is False
        assert len(result["errors"]) >= 1
        assert "denied" in result["errors"][0]

    @patch('passkey.mcp_server.get_entry')
    def test_config_file_not_found(self, mock_get, tmp_path):
        config_path = tmp_path / "nonexistent.json"

        mock_get.return_value = Entry(name="myserver", fields={"TOKEN": "value"})
        result = passkey_setup_server("myserver", config_paths=[str(config_path)])
        assert len(result["errors"]) >= 1
        assert "not found" in result["errors"][0].lower()


class TestPasskeyDoctor:
    """Tests for passkey_doctor tool."""

    def _make_adapter(self, tmp_path, root_key="mcpServers"):
        import sys

        from passkey.mcp_config import ToolAdapter
        cfg = tmp_path / "config.json"
        cfg.touch()
        return ToolAdapter(
            name="test", display_name="Test", root_key=root_key,
            global_paths={sys.platform: cfg}, project_paths={},
        )

    @patch('passkey.mcp_server.load_config')
    def test_detects_missing_config(self, mock_load):
        mock_load.side_effect = FileNotFoundError()
        result = passkey_doctor()
        assert result["summary"]["failed"] > 0

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.find_passkey_command')
    @patch('passkey.mcp_server.load_config')
    def test_detects_missing_passkey_in_path(self, mock_load, mock_find, mock_list):
        mock_load.return_value = {"mcpServers": {}}
        mock_find.return_value = None
        mock_list.return_value = []
        result = passkey_doctor()
        assert any(c["status"] == "fail" and "passkey_in_path" in c["name"] for c in result["checks"])

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.find_passkey_command')
    @patch('passkey.mcp_server.load_config')
    def test_all_checks_pass(self, mock_load, mock_find, mock_list):
        mock_load.return_value = {"mcpServers": {}}
        mock_find.return_value = "/usr/local/bin/passkey"
        mock_list.return_value = []
        result = passkey_doctor()
        assert result["summary"]["failed"] == 0

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.find_passkey_command')
    @patch('passkey.mcp_server.load_config')
    def test_reports_broken_server(self, mock_load, mock_find, mock_list, tmp_path):
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {
            "mcpServers": {
                "myserver": {
                    "command": "passkey",
                    "args": ["run", "myserver", "--", "python"],
                }
            }
        }
        mock_find.return_value = "/usr/local/bin/passkey"
        mock_list.return_value = []
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_doctor()
        assert any("broken" in i.lower() or "missing" in i.lower() for i in result["issues"])

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.find_passkey_command')
    @patch('passkey.mcp_server.load_config')
    def test_reports_exposed_server(self, mock_load, mock_find, mock_list, tmp_path):
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {
            "mcpServers": {
                "myserver": {
                    "command": "python",
                    "env": {"API_TOKEN": "secret123"},
                }
            }
        }
        mock_find.return_value = "/usr/local/bin/passkey"
        mock_list.return_value = []
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_doctor()
        assert any("exposed" in i.lower() for i in result["issues"])

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.find_passkey_command')
    @patch('passkey.mcp_server.load_config')
    def test_handles_keychain_failure(self, mock_load, mock_find, mock_list, tmp_path):
        from passkey.keychain import PasskeyError
        adapter = self._make_adapter(tmp_path)
        mock_load.return_value = {"mcpServers": {}}
        mock_find.return_value = "/usr/local/bin/passkey"
        mock_list.side_effect = PasskeyError("Access denied")
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_doctor()
        assert any(c["status"] == "fail" and "keychain" in c["name"] for c in result["checks"])

    @patch('passkey.mcp_server.list_entries')
    @patch('passkey.mcp_server.find_passkey_command')
    @patch('passkey.mcp_server.load_config')
    def test_handles_invalid_adapter_config(self, mock_load, mock_find, mock_list, tmp_path):
        from passkey.mcp_config import MCPConfigError
        adapter = self._make_adapter(tmp_path)
        mock_find.return_value = "/usr/local/bin/passkey"
        mock_list.return_value = []
        # Make load_config fail with MCPConfigError to simulate invalid JSON
        mock_load.side_effect = MCPConfigError("Broken config")
        with patch('passkey.mcp_server.ADAPTERS', {"test": adapter}):
            result = passkey_doctor()
        assert any(c["status"] == "fail" and "config" in c["name"] for c in result["checks"])
