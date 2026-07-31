"""Tests for passkey.mcp_config module — adapter-specific operations."""

import json
import sys

import pytest

from passkey.mcp_config import (
    ADAPTERS,
    ToolAdapter,
    find_adapter_for_path,
    get_env_from_server,
    get_mcp_servers,
    load_config,
    save_config,
    set_env_on_server,
    set_mcp_servers,
)


class TestMultiAdapterRootKeys:
    """Test get_mcp_servers/set_mcp_servers with different root_keys."""

    @pytest.fixture
    def base_config(self):
        return {
            "mcpServers": {"srv1": {"command": "node"}},
            "servers": {"srv2": {"command": "node"}},
            "context_servers": {"srv4": {"command": "node"}},
        }

    def test_claude_adapter_uses_mcpServers(self, base_config):
        adapter = ADAPTERS["claude"]
        servers = get_mcp_servers(base_config, adapter)
        assert "srv1" in servers

    def test_vscode_adapter_uses_servers(self, base_config):
        adapter = ADAPTERS["vscode"]
        servers = get_mcp_servers(base_config, adapter)
        assert "srv2" in servers

    def test_opencode_adapter_root_key_is_mcp(self):
        assert ADAPTERS["opencode"].root_key == "mcp"

    def test_zed_adapter_uses_context_servers(self, base_config):
        adapter = ADAPTERS["zed"]
        servers = get_mcp_servers(base_config, adapter)
        assert "srv4" in servers

    def test_mcp_servers_defaults_to_empty(self):
        adapter = ADAPTERS["claude"]
        servers = get_mcp_servers({}, adapter)
        assert servers == {}

    def test_set_mcp_servers_claude(self):
        adapter = ADAPTERS["claude"]
        config = {}
        set_mcp_servers(config, adapter, {"my-srv": {"command": "python"}})
        assert config["mcpServers"]["my-srv"]["command"] == "python"

    def test_set_mcp_servers_vscode(self):
        adapter = ADAPTERS["vscode"]
        config = {}
        set_mcp_servers(config, adapter, {"my-srv": {"command": "python"}})
        assert config["servers"]["my-srv"]["command"] == "python"

    def test_set_mcp_servers_opencode(self):
        adapter = ADAPTERS["opencode"]
        config = {}
        set_mcp_servers(config, adapter, {"my-srv": {"command": "python"}})
        assert config["mcp"]["my-srv"]["command"] == "python"


class TestMultiAdapterEnvKeys:
    """Test get_env_from_server/set_env_on_server with different env_keys."""

    def test_claude_uses_env(self):
        adapter = ADAPTERS["claude"]
        server = {"env": {"TOKEN": "x"}}
        assert get_env_from_server(server, adapter) == {"TOKEN": "x"}

    def test_opencode_uses_environment(self):
        adapter = ADAPTERS["opencode"]
        server = {"environment": {"TOKEN": "x"}}
        assert get_env_from_server(server, adapter) == {"TOKEN": "x"}

    def test_claude_set_env(self):
        adapter = ADAPTERS["claude"]
        server = {}
        set_env_on_server(server, adapter, {"TOKEN": "x"})
        assert server["env"] == {"TOKEN": "x"}

    def test_opencode_set_env(self):
        adapter = ADAPTERS["opencode"]
        server = {}
        set_env_on_server(server, adapter, {"TOKEN": "x"})
        assert server["environment"] == {"TOKEN": "x"}

    def test_set_env_removes_key_when_empty(self):
        adapter = ADAPTERS["claude"]
        server = {"env": {"TOKEN": "x"}}
        set_env_on_server(server, adapter, {})
        assert "env" not in server


class TestOpenCodeArrayCommand:
    """Test rewrite_server_for_passkey with command_is_array=True."""

    def test_rewrite_array_command(self):
        from passkey.mcp_config import rewrite_server_for_passkey
        adapter = ADAPTERS["opencode"]
        original = {
            "command": ["python", "-m", "server"],
            "args": ["--verbose"],
            "environment": {"TOKEN": "secret"},
        }
        result = rewrite_server_for_passkey("myserver", original, adapter)
        assert result["command"] == ["passkey", "run", "myserver", "--", "python", "-m", "server"]
        assert result["args"] == ["--verbose"]
        assert "environment" not in result  # TOKEN removed as secret

    def test_rewrite_array_command_no_env(self):
        from passkey.mcp_config import rewrite_server_for_passkey
        adapter = ADAPTERS["opencode"]
        original = {"command": ["python", "-m", "server"]}
        result = rewrite_server_for_passkey("myserver", original, adapter)
        assert result["command"] == ["passkey", "run", "myserver", "--", "python", "-m", "server"]

    def test_is_passkey_wrapped_array(self):
        from passkey.mcp_config import is_passkey_wrapped
        wrapped = {"command": ["passkey", "run", "myserver", "--", "node"]}
        assert is_passkey_wrapped(wrapped) is True
        not_wrapped = {"command": ["python", "-m", "server"]}
        assert is_passkey_wrapped(not_wrapped) is False

    def test_get_original_command_array_format(self):
        from passkey.mcp_config import get_original_command
        # Note: get_original_command only looks at args, not command
        config = {"command": ["passkey"], "args": ["run", "myserver", "--", "node", "app.js"]}
        cmd, args = get_original_command(config)
        assert cmd == "node"
        assert args == ["app.js"]


class TestFindAdapterForPath:
    """Test adapter path matching."""

    def test_finds_claude_adapter(self, tmp_path):
        adapter = ADAPTERS["claude"]
        path = adapter.get_global_path()
        if path:  # Only run if current platform has a path defined
            result = find_adapter_for_path(path)
            assert result is not None
            assert result.name == "claude"

    def test_finds_vscode_adapter(self, tmp_path):
        adapter = ADAPTERS["vscode"]
        path = adapter.get_global_path()
        if path:
            result = find_adapter_for_path(path)
            assert result is not None
            assert result.name == "vscode"

    def test_finds_opencode_adapter(self, tmp_path):
        adapter = ADAPTERS["opencode"]
        path = adapter.get_global_path()
        if path:
            result = find_adapter_for_path(path)
            assert result is not None
            assert result.name == "opencode"

    def test_returns_none_for_unknown_path(self, tmp_path):
        result = find_adapter_for_path(tmp_path / "random" / "unknown.json")
        assert result is None


class TestLoadConfig:
    """Tests for load_config with various formats."""

    def test_loads_valid_json(self, tmp_path):
        f = tmp_path / "config.json"
        f.write_text('{"mcpServers": {"test": {"command": "node"}}}')
        result = load_config(f)
        assert result["mcpServers"]["test"]["command"] == "node"

    def test_loads_jsonc_with_line_comments(self, tmp_path):
        """JSONC with // comments should parse."""
        f = tmp_path / "config.jsonc"
        f.write_text('{\n  // This is a comment\n  "key": "value"\n}')
        result = load_config(f)
        assert result["key"] == "value"

    def test_loads_jsonc_with_block_comments(self, tmp_path):
        """JSONC with /* */ comments should parse."""
        f = tmp_path / "config.jsonc"
        f.write_text('{\n  /* block comment */\n  "key": "value"\n}')
        result = load_config(f)
        assert result["key"] == "value"

    def test_raises_for_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        with pytest.raises(Exception):
            load_config(f)

    def test_jsonc_preserves_urls_in_strings(self, tmp_path):
        """Regression: // inside string literals (URLs) must survive."""
        f = tmp_path / "opencode.json"
        f.write_text("""{
  // Remote MCP server
  "mcp": {
    "remote": {
      "type": "remote",
      "url": "https://mcp.example.com/sse", // trailing comment
      "enabled": true
    }
  }
}""")
        result = load_config(f)
        assert result["mcp"]["remote"]["url"] == "https://mcp.example.com/sse"
        assert result["mcp"]["remote"]["enabled"] is True

    def test_jsonc_block_comment_with_url_inside_string(self, tmp_path):
        """Block comments stripped, strings with // and /* kept verbatim."""
        f = tmp_path / "settings.json"
        f.write_text('''{
  /* multi
     line */
  "callback": "https://example.com/a/*wild*/path",
  "note": "say // hi"
}''')
        result = load_config(f)
        assert result["callback"] == "https://example.com/a/*wild*/path"
        assert result["note"] == "say // hi"

    def test_jsonc_escaped_quotes_in_strings(self, tmp_path):
        """Escaped quotes must not confuse the string state machine."""
        f = tmp_path / "config.json"
        f.write_text('{"a": "quote \\" here", "b": 1} // done')
        result = load_config(f)
        assert result["a"] == 'quote " here'
        assert result["b"] == 1

    def test_raises_for_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.json")

    def test_handles_json_inside_brackets(self, tmp_path):
        """Just a value (not dict) should work."""
        f = tmp_path / "config.json"
        f.write_text('["a", "b"]')
        result = load_config(f)
        assert result == ["a", "b"]


class TestSaveConfig:
    """Tests for atomic config save."""

    def test_saves_json(self, tmp_path):
        config_path = tmp_path / "config.json"
        save_config({"key": "value"}, config_path)
        assert config_path.exists()
        data = json.loads(config_path.read_text())
        assert data["key"] == "value"

    def test_saves_pretty_printed(self, tmp_path):
        config_path = tmp_path / "config.json"
        save_config({"nested": {"a": 1}}, config_path)
        content = config_path.read_text()
        assert content == '{\n  "nested": {\n    "a": 1\n  }\n}\n'

    def test_atomic_write_leaves_original_on_error(self, tmp_path):
        """If the parent dir doesn't exist, the original file is untouched."""
        config_path = tmp_path / "nonexistent" / "config.json"
        with pytest.raises(OSError):
            save_config({"key": "value"}, config_path)

    def test_overwrites_existing_file(self, tmp_path):
        config_path = tmp_path / "config.json"
        config_path.write_text('{"old": "data"}')
        save_config({"new": "data"}, config_path)
        data = json.loads(config_path.read_text())
        assert data["new"] == "data"
        assert "old" not in data


class TestGetAllConfigPaths:
    """Tests for adapter path enumeration."""

    def test_returns_only_existing_paths(self, tmp_path):
        existing = tmp_path / "exists.json"
        existing.touch()
        adapter = ToolAdapter(
            name="test", display_name="Test", root_key="mcpServers",
            global_paths={sys.platform: existing},
            project_paths={sys.platform: tmp_path / "nope.json"},
        )
        paths = adapter.get_all_existing_paths()
        assert existing in paths
        assert tmp_path / "nope.json" not in paths
