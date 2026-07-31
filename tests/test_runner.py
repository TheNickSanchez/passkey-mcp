"""Tests for passkey.runner module."""

from unittest.mock import MagicMock, patch

import pytest

from passkey.models import Entry
from passkey.runner import run_with_secrets


class TestRunWithSecrets:
    """Tests for run_with_secrets()."""

    @patch('passkey.runner.subprocess.run')
    @patch('passkey.runner.get_entry')
    def test_loads_both_secrets_and_config(self, mock_get_entry, mock_run):
        """Both secret and config fields are loaded into env."""
        mock_entry = Entry(
            name="test",
            fields={"TOKEN": "secret123"},
            config={"URL": "https://example.com"}
        )
        mock_get_entry.return_value = mock_entry
        mock_run.return_value = MagicMock(returncode=0)

        rc = run_with_secrets(["test"], ["echo", "hello"])
        assert rc == 0

        call_kwargs = mock_run.call_args.kwargs
        env = call_kwargs.get('env', {})
        assert env.get("TOKEN") == "secret123"
        assert env.get("URL") == "https://example.com"

    @patch('passkey.runner.subprocess.run')
    @patch('passkey.runner.get_entry')
    def test_secrets_override_config_same_key(self, mock_get_entry, mock_run):
        """If same key exists in both, secret value takes priority."""
        mock_entry = Entry(
            name="test",
            fields={"VALUE": "secret_value"},
            config={"VALUE": "config_value"}
        )
        mock_get_entry.return_value = mock_entry
        mock_run.return_value = MagicMock(returncode=0)

        rc = run_with_secrets(["test"], ["echo"])
        assert rc == 0

        call_kwargs = mock_run.call_args.kwargs
        env = call_kwargs.get('env', {})
        assert env.get("VALUE") == "secret_value"

    @patch('passkey.runner.subprocess.run')
    @patch('passkey.runner.get_entry')
    def test_backwards_compat_no_config(self, mock_get_entry, mock_run):
        """Works with entries that have no config (backwards compat)."""
        mock_entry = Entry(name="legacy", fields={"TOKEN": "abc"})
        mock_get_entry.return_value = mock_entry
        mock_run.return_value = MagicMock(returncode=0)

        rc = run_with_secrets(["legacy"], ["cmd"])
        assert rc == 0
        call_kwargs = mock_run.call_args.kwargs
        env = call_kwargs.get('env', {})
        assert env.get("TOKEN") == "abc"

    @patch('passkey.runner.subprocess.run')
    @patch('passkey.runner.get_entry')
    def test_multiple_entries_merge(self, mock_get_entry, mock_run):
        """Multiple entries merge their env vars."""
        entry1 = Entry(
            name="entry1",
            fields={"TOKEN1": "secret1"},
            config={"URL1": "https://one.com"}
        )
        entry2 = Entry(
            name="entry2",
            fields={"TOKEN2": "secret2"},
            config={"URL2": "https://two.com"}
        )
        mock_get_entry.side_effect = [entry1, entry2]
        mock_run.return_value = MagicMock(returncode=0)

        rc = run_with_secrets(["entry1", "entry2"], ["cmd"])
        assert rc == 0
        call_kwargs = mock_run.call_args.kwargs
        env = call_kwargs.get('env', {})
        assert env.get("TOKEN1") == "secret1"
        assert env.get("TOKEN2") == "secret2"
        assert env.get("URL1") == "https://one.com"
        assert env.get("URL2") == "https://two.com"

    @patch('passkey.runner.get_entry')
    def test_exits_when_no_entries_found(self, mock_get_entry):
        """Raises PasskeyError when no entries are found."""
        from passkey.keychain import PasskeyError
        mock_get_entry.return_value = None

        with pytest.raises(PasskeyError) as exc_info:
            run_with_secrets(["nonexistent"], ["cmd"])

        assert "No entries loaded, aborting command" in str(exc_info.value)

    @patch('passkey.runner.subprocess.run')
    @patch('passkey.runner.get_entry')
    def test_preserves_existing_env(self, mock_get_entry, mock_run, monkeypatch):
        """Existing environment variables are preserved."""
        monkeypatch.setenv("EXISTING_VAR", "existing_value")

        mock_entry = Entry(
            name="test",
            fields={"NEW_VAR": "new_value"},
            config={}
        )
        mock_get_entry.return_value = mock_entry
        mock_run.return_value = MagicMock(returncode=0)

        rc = run_with_secrets(["test"], ["cmd"])
        assert rc == 0

        call_kwargs = mock_run.call_args.kwargs
        env = call_kwargs.get('env', {})
        assert env.get("EXISTING_VAR") == "existing_value"
        assert env.get("NEW_VAR") == "new_value"
