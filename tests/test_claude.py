"""Tests for passkey.claude module."""


import pytest

from passkey.claude import (
    ClaudeConfigError,
    extract_secrets,
    get_original_command,
    get_server_security_status,
    is_likely_secret,
    is_passkey_wrapped,
    load_claude_config,
    rewrite_server_for_passkey,
)
from passkey.mcp_config import ADAPTERS

CLAUDE_ADAPTER = ADAPTERS["claude"]


class TestIsLikelySecret:
    """Tests for is_likely_secret()."""

    def test_detects_token_vars(self):
        """Detects TOKEN in variable name."""
        assert is_likely_secret("SLACK_TOKEN") is True
        assert is_likely_secret("API_TOKEN") is True
        assert is_likely_secret("OAUTH_TOKEN") is True

    def test_detects_secret_vars(self):
        """Detects SECRET in variable name."""
        assert is_likely_secret("CLIENT_SECRET") is True
        assert is_likely_secret("JAMF_CLIENT_SECRET") is True
        assert is_likely_secret("SECRET_KEY") is True

    def test_detects_password_vars(self):
        """Detects PASSWORD in variable name."""
        assert is_likely_secret("DB_PASSWORD") is True
        assert is_likely_secret("JAMF_PASSWORD") is True
        assert is_likely_secret("PASSWORD") is True

    def test_detects_key_vars(self):
        """Detects KEY in variable name."""
        assert is_likely_secret("API_KEY") is True
        assert is_likely_secret("PRIVATE_KEY") is True

    def test_detects_id_vars(self):
        """Detects _ID suffix in variable name."""
        assert is_likely_secret("CLIENT_ID") is True
        assert is_likely_secret("TENANT_ID") is True

    def test_excludes_non_secret_vars(self):
        """Excludes common non-secret variables."""
        assert is_likely_secret("PYTHONPATH") is False
        assert is_likely_secret("PATH") is False
        assert is_likely_secret("HOME") is False
        assert is_likely_secret("USER") is False
        assert is_likely_secret("NODE_ENV") is False

    def test_case_insensitive(self):
        """Detection is case insensitive."""
        assert is_likely_secret("api_token") is True
        assert is_likely_secret("Api_Token") is True
        assert is_likely_secret("API_TOKEN") is True


class TestExtractSecrets:
    """Tests for extract_secrets()."""

    def test_separates_secrets_and_non_secrets(self):
        """Correctly separates secrets from non-secrets."""
        env = {
            "API_TOKEN": "secret123",
            "PYTHONPATH": "/path/to/lib",
            "CLIENT_SECRET": "shhh",
            "NODE_ENV": "production",
        }

        secrets, non_secrets = extract_secrets(env)

        assert secrets == {"API_TOKEN": "secret123", "CLIENT_SECRET": "shhh"}
        assert non_secrets == {"PYTHONPATH": "/path/to/lib", "NODE_ENV": "production"}

    def test_empty_env(self):
        """Handles empty env dict."""
        secrets, non_secrets = extract_secrets({})
        assert secrets == {}
        assert non_secrets == {}

    def test_all_secrets(self):
        """Handles env with only secrets."""
        env = {"TOKEN": "abc", "PASSWORD": "xyz"}
        secrets, non_secrets = extract_secrets(env)
        assert secrets == env
        assert non_secrets == {}

    def test_no_secrets(self):
        """Handles env with no secrets."""
        env = {"PYTHONPATH": "/lib", "HOME": "/home/user"}
        secrets, non_secrets = extract_secrets(env)
        assert secrets == {}
        assert non_secrets == env


class TestIsPasskeyWrapped:
    """Tests for is_passkey_wrapped()."""

    def test_detects_passkey_command(self):
        """Detects when command is passkey."""
        config = {"command": "passkey", "args": ["run", "entry", "--", "cmd"]}
        assert is_passkey_wrapped(config) is True

    def test_detects_full_path_passkey(self):
        """Detects passkey with full path."""
        config = {"command": "/usr/local/bin/passkey", "args": ["run", "entry"]}
        assert is_passkey_wrapped(config) is True

    def test_not_passkey(self):
        """Returns False for non-passkey commands."""
        config = {"command": "python", "args": ["-m", "server"]}
        assert is_passkey_wrapped(config) is False

    def test_missing_command(self):
        """Handles missing command key."""
        config = {"args": ["run", "something"]}
        assert is_passkey_wrapped(config) is False


class TestRewriteServerForPasskey:
    """Tests for rewrite_server_for_passkey()."""

    def test_basic_rewrite(self):
        """Basic server config rewrite."""
        original = {
            "command": "python",
            "args": ["-m", "myserver"],
            "env": {"API_TOKEN": "secret", "PYTHONPATH": "/lib"}
        }

        result = rewrite_server_for_passkey("myserver", original, CLAUDE_ADAPTER)

        assert result["command"] == "passkey"
        assert result["args"] == ["run", "myserver", "--", "python", "-m", "myserver"]
        assert result["env"] == {"PYTHONPATH": "/lib"}

    def test_preserves_type(self):
        """Preserves type field."""
        original = {
            "type": "stdio",
            "command": "python",
            "args": [],
            "env": {"TOKEN": "x"}
        }

        result = rewrite_server_for_passkey("test", original, CLAUDE_ADAPTER)

        assert result["type"] == "stdio"

    def test_no_env_in_result_if_only_secrets(self):
        """Omits env if only secrets (no non-secrets)."""
        original = {
            "command": "python",
            "args": [],
            "env": {"TOKEN": "secret", "PASSWORD": "pass"}
        }

        result = rewrite_server_for_passkey("test", original, CLAUDE_ADAPTER)

        assert "env" not in result

    def test_no_original_env(self):
        """Handles server with no env."""
        original = {"command": "python", "args": ["-m", "server"]}

        result = rewrite_server_for_passkey("test", original, CLAUDE_ADAPTER)

        assert result["command"] == "passkey"
        assert "env" not in result


class TestGetOriginalCommand:
    """Tests for get_original_command()."""

    def test_extracts_command_after_separator(self):
        """Extracts original command from passkey args."""
        config = {
            "command": "passkey",
            "args": ["run", "entry", "--", "python", "-m", "server"]
        }

        cmd, args = get_original_command(config)

        assert cmd == "python"
        assert args == ["-m", "server"]

    def test_no_separator(self):
        """Returns empty when no -- separator."""
        config = {"command": "passkey", "args": ["run", "entry"]}

        cmd, args = get_original_command(config)

        assert cmd == ""
        assert args == []

    def test_nothing_after_separator(self):
        """Handles -- with nothing after."""
        config = {"command": "passkey", "args": ["run", "entry", "--"]}

        cmd, args = get_original_command(config)

        assert cmd == ""
        assert args == []


class TestGetServerSecurityStatus:
    """Tests for get_server_security_status()."""

    def test_secured_status(self):
        """Detects fully secured server."""
        config = {
            "command": "passkey",
            "args": ["run", "myserver", "--", "python", "-m", "server"],
            "env": {"PYTHONPATH": "/lib"}
        }
        entries = ["myserver"]

        result = get_server_security_status("myserver", config, entries, CLAUDE_ADAPTER)

        assert result["status"] == "secured"
        assert result["passkey_entry"] == "myserver"
        assert result["exposed_secrets"] == []

    def test_exposed_status(self):
        """Detects exposed secrets."""
        config = {
            "command": "python",
            "args": ["-m", "server"],
            "env": {"API_TOKEN": "secret"}
        }
        entries = []

        result = get_server_security_status("myserver", config, entries, CLAUDE_ADAPTER)

        assert result["status"] == "exposed"
        assert result["exposed_secrets"] == ["API_TOKEN"]

    def test_partial_status(self):
        """Detects partial security (passkey + exposed)."""
        config = {
            "command": "passkey",
            "args": ["run", "myserver", "--", "python"],
            "env": {"LEFTOVER_TOKEN": "oops"}
        }
        entries = ["myserver"]

        result = get_server_security_status("myserver", config, entries, CLAUDE_ADAPTER)

        assert result["status"] == "partial"
        assert result["exposed_secrets"] == ["LEFTOVER_TOKEN"]

    def test_broken_status(self):
        """Detects broken config (passkey but no entry)."""
        config = {
            "command": "passkey",
            "args": ["run", "myserver", "--", "python"]
        }
        entries = []  # Entry missing!

        result = get_server_security_status("myserver", config, entries, CLAUDE_ADAPTER)

        assert result["status"] == "broken"

    def test_no_secrets_status(self):
        """Detects server with no secrets to protect."""
        config = {
            "command": "python",
            "args": ["-m", "server"],
            "env": {"PYTHONPATH": "/lib"}
        }
        entries = []

        result = get_server_security_status("myserver", config, entries, CLAUDE_ADAPTER)

        assert result["status"] == "no_secrets"


class TestLoadClaudeConfig:
    """Tests for load_claude_config()."""

    def test_loads_valid_json(self, tmp_path):
        """Loads valid JSON config."""
        config_file = tmp_path / ".claude.json"
        config_file.write_text('{"mcpServers": {}}')

        result = load_claude_config(config_file)

        assert result == {"mcpServers": {}}

    def test_raises_on_missing_file(self, tmp_path):
        """Raises FileNotFoundError for missing file."""
        config_file = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError):
            load_claude_config(config_file)

    def test_raises_on_invalid_json(self, tmp_path):
        """Raises ClaudeConfigError for invalid JSON."""
        config_file = tmp_path / ".claude.json"
        config_file.write_text("not valid json {")

        with pytest.raises(ClaudeConfigError):
            load_claude_config(config_file)
