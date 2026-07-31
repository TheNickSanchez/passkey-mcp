"""Tests for passkey unwrap: restore_server_from_passkey + cmd_unwrap."""

import json
import sys
from unittest.mock import patch

import pytest

from passkey.mcp_commands import cmd_unwrap
from passkey.mcp_config import (
    ADAPTERS,
    ToolAdapter,
    get_original_command,
    restore_server_from_passkey,
    rewrite_server_for_passkey,
)

CLAUDE = ADAPTERS["claude"]
OPENCODE = ADAPTERS["opencode"]

WRAPPED_STANDARD = {
    "command": "passkey",
    "args": ["run", "slack", "--", "npx", "-y", "@slack/mcp"],
    "env": {"NODE_ENV": "production"},
}

WRAPPED_ARRAY = {
    "command": ["passkey", "run", "slack", "--", "npx", "-y", "@slack/mcp"],
    "args": ["--port", "3000"],
    "environment": {"NODE_ENV": "production"},
}


class TestGetOriginalCommand:
    def test_standard_form(self):
        cmd, args = get_original_command(WRAPPED_STANDARD)
        assert cmd == "npx"
        assert args == ["-y", "@slack/mcp"]

    def test_array_form(self):
        cmd, args = get_original_command(WRAPPED_ARRAY)
        assert cmd == "npx"
        # Original "args" (["--port", "3000"]) are preserved separately,
        # not merged into the command tail.
        assert args == ["-y", "@slack/mcp"]

    def test_not_wrapped(self):
        assert get_original_command({"command": "node", "args": ["x.js"]}) == ("", [])

    def test_empty_after_separator(self):
        cfg = {"command": "passkey", "args": ["run", "x", "--"]}
        assert get_original_command(cfg) == ("", [])


class TestRestoreServer:
    def test_roundtrip_standard(self):
        original = {
            "command": "npx",
            "args": ["-y", "@slack/mcp"],
            "env": {"SLACK_TOKEN": "xoxb-secret", "NODE_ENV": "production"},
        }
        wrapped = rewrite_server_for_passkey("slack", original, CLAUDE)
        restored = restore_server_from_passkey(wrapped, CLAUDE)
        assert restored["command"] == "npx"
        assert restored["args"] == ["-y", "@slack/mcp"]
        # Non-secret env kept, secrets NOT restored by default
        assert restored["env"] == {"NODE_ENV": "production"}

    def test_roundtrip_standard_with_secrets(self):
        original = {
            "command": "npx",
            "args": ["-y", "@slack/mcp"],
            "env": {"SLACK_TOKEN": "xoxb-secret", "NODE_ENV": "production"},
        }
        wrapped = rewrite_server_for_passkey("slack", original, CLAUDE)
        restored = restore_server_from_passkey(
            wrapped, CLAUDE, secrets={"SLACK_TOKEN": "xoxb-secret"}
        )
        assert restored["env"] == {
            "NODE_ENV": "production",
            "SLACK_TOKEN": "xoxb-secret",
        }

    def test_roundtrip_array(self):
        original = {
            "command": ["npx", "-y", "@slack/mcp"],
            "args": ["--port", "3000"],
            "environment": {"NODE_ENV": "production"},
        }
        wrapped = rewrite_server_for_passkey("slack", original, OPENCODE)
        assert wrapped["command"][0] == "passkey"
        restored = restore_server_from_passkey(wrapped, OPENCODE)
        assert restored["command"] == ["npx", "-y", "@slack/mcp"]
        assert restored["args"] == ["--port", "3000"]
        assert restored["environment"] == {"NODE_ENV": "production"}

    def test_preserves_type(self):
        wrapped = {"type": "stdio", **WRAPPED_STANDARD}
        restored = restore_server_from_passkey(wrapped, CLAUDE)
        assert restored["type"] == "stdio"


def _write_claude_config(tmp_path, servers):
    path = tmp_path / "claude.json"
    path.write_text(json.dumps({"mcpServers": servers}))
    return path


class TestCmdUnwrap:
    def test_unwrap_restores_inline_command(self, tmp_path, capsys):
        config_path = _write_claude_config(tmp_path, {"slack": dict(WRAPPED_STANDARD)})
        cmd_unwrap(tool="claude", config_path=str(config_path))
        data = json.loads(config_path.read_text())
        slack = data["mcpServers"]["slack"]
        assert slack["command"] == "npx"
        assert slack["args"] == ["-y", "@slack/mcp"]
        assert slack["env"] == {"NODE_ENV": "production"}
        # Secrets not restored by default
        assert "SLACK_TOKEN" not in slack.get("env", {})
        # Backup created
        assert (tmp_path / "claude.json.backup").exists()

    def test_unwrap_dry_run_writes_nothing(self, tmp_path):
        config_path = _write_claude_config(tmp_path, {"slack": dict(WRAPPED_STANDARD)})
        before = config_path.read_text()
        cmd_unwrap(tool="claude", config_path=str(config_path), dry_run=True)
        assert config_path.read_text() == before
        assert not (tmp_path / "claude.json.backup").exists()

    def test_unwrap_specific_server_only(self, tmp_path):
        config_path = _write_claude_config(tmp_path, {
            "slack": dict(WRAPPED_STANDARD),
            "github": {
                "command": "passkey",
                "args": ["run", "github", "--", "gh-mcp"],
            },
        })
        cmd_unwrap(tool="claude", config_path=str(config_path), server="slack")
        data = json.loads(config_path.read_text())
        assert data["mcpServers"]["slack"]["command"] == "npx"
        # github left wrapped
        assert data["mcpServers"]["github"]["command"] == "passkey"

    def test_unwrap_restore_secrets(self, tmp_path):
        config_path = _write_claude_config(tmp_path, {"slack": dict(WRAPPED_STANDARD)})
        from passkey.models import Entry

        entry = Entry(name="slack", fields={"SLACK_TOKEN": "xoxb-secret"})
        with patch("passkey.mcp_commands.get_entry", return_value=entry):
            cmd_unwrap(tool="claude", config_path=str(config_path), restore_secrets=True)
        data = json.loads(config_path.read_text())
        assert data["mcpServers"]["slack"]["env"]["SLACK_TOKEN"] == "xoxb-secret"

    def test_nothing_to_unwrap(self, tmp_path, capsys):
        config_path = _write_claude_config(tmp_path, {
            "plain": {"command": "node", "args": ["srv.js"]},
        })
        cmd_unwrap(tool="claude", config_path=str(config_path))
        assert "Nothing to unwrap" in capsys.readouterr().out

    def test_unknown_config_path_rejected(self, tmp_path):
        from passkey.keychain import PasskeyError
        weird = tmp_path / "random.json"
        weird.write_text("{}")
        with pytest.raises(PasskeyError):
            cmd_unwrap(config_path=str(weird))


class TestUnwrapViaToolDetection:
    """cmd_unwrap without --config uses adapter path discovery."""

    def test_tool_with_no_configs(self, tmp_path, monkeypatch, capsys):
        empty_adapter = ToolAdapter(
            name="empty", display_name="Empty", root_key="mcpServers",
            global_paths={sys.platform: tmp_path / "nope.json"},
        )
        with patch.dict(ADAPTERS, {"empty": empty_adapter}, clear=True):
            cmd_unwrap(tool="empty")
        assert "No config files found" in capsys.readouterr().out
