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


class TestPasskeySetupServer:
    """Tests for passkey_setup_server tool."""

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


class TestPasskeyDoctor:
    """Tests for passkey_doctor tool."""

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
