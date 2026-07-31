"""Tests for interactive CLI components."""

from unittest.mock import patch

import pytest

from passkey.interactive import (
    fuzzy_match,
    is_interactive,
    select_entry,
    select_field,
)
from passkey.keychain import PasskeyError
from passkey.models import Entry


class TestIsInteractive:
    """Tests for TTY detection."""

    @patch('sys.stdin')
    @patch('sys.stdout')
    def test_returns_true_when_both_tty(self, mock_stdout, mock_stdin):
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = True
        assert is_interactive() is True

    @patch('sys.stdin')
    @patch('sys.stdout')
    def test_returns_false_when_stdin_not_tty(self, mock_stdout, mock_stdin):
        mock_stdin.isatty.return_value = False
        mock_stdout.isatty.return_value = True
        assert is_interactive() is False

    @patch('sys.stdin')
    @patch('sys.stdout')
    def test_returns_false_when_stdout_not_tty(self, mock_stdout, mock_stdin):
        mock_stdin.isatty.return_value = True
        mock_stdout.isatty.return_value = False
        assert is_interactive() is False


class TestFuzzyMatch:
    """Tests for fuzzy matching."""

    def test_empty_query_returns_all(self):
        choices = ["apple", "banana", "cherry"]
        result = fuzzy_match("", choices)
        assert result == choices

    def test_prefix_match(self):
        choices = ["jamf", "jamf_api_read", "jamf_api_write", "slack"]
        result = fuzzy_match("jamf_", choices)
        assert result == ["jamf_api_read", "jamf_api_write"]

    def test_contains_match(self):
        choices = ["jamf_api_read", "jamf_api_write", "slack"]
        result = fuzzy_match("api", choices)
        assert "jamf_api_read" in result
        assert "jamf_api_write" in result
        assert "slack" not in result

    def test_fuzzy_character_match(self):
        choices = ["servicenow", "slack", "github"]
        result = fuzzy_match("sn", choices)
        assert "servicenow" in result

    def test_case_insensitive(self):
        choices = ["JAMF", "Slack", "GitHub"]
        result = fuzzy_match("jamf", choices)
        assert "JAMF" in result

    def test_no_matches_returns_empty(self):
        choices = ["apple", "banana", "cherry"]
        result = fuzzy_match("xyz", choices)
        assert result == []

    def test_prefix_match_sorted_first(self):
        choices = ["api_helper", "jamf_api_read", "slack"]
        result = fuzzy_match("api", choices)
        # Prefix match should come before contains match
        assert result[0] == "api_helper"


class TestSelectEntry:
    """Tests for entry selection."""

    @patch('passkey.interactive.list_entries')
    def test_exits_when_no_entries(self, mock_list):
        mock_list.return_value = []
        with pytest.raises(PasskeyError):
            select_entry()

    @patch('passkey.interactive.list_entries')
    def test_single_fuzzy_match_returns_directly(self, mock_list):
        mock_list.return_value = ["slack", "github", "jamf"]
        result = select_entry(filter_prefix="sla")
        assert result == "slack"

    @patch('passkey.interactive.list_entries')
    def test_no_fuzzy_match_exits(self, mock_list):
        mock_list.return_value = ["slack", "github"]
        with pytest.raises(PasskeyError):
            select_entry(filter_prefix="nonexistent")

    @patch('passkey.interactive.is_interactive')
    @patch('passkey.interactive.list_entries')
    def test_multiple_matches_exits_when_not_interactive(self, mock_list, mock_interactive):
        mock_list.return_value = ["jamf_api_read", "jamf_api_write", "slack"]
        mock_interactive.return_value = False
        with pytest.raises(PasskeyError):
            select_entry(filter_prefix="jamf")


class TestSelectField:
    """Tests for field selection."""

    @patch('passkey.interactive.get_entry')
    def test_exits_when_entry_not_found(self, mock_get):
        mock_get.return_value = None
        with pytest.raises(PasskeyError):
            select_field("nonexistent")

    @patch('passkey.interactive.get_entry')
    def test_single_field_returns_directly(self, mock_get):
        mock_entry = Entry(name="test", fields={"ONLY_FIELD": "value"})
        mock_get.return_value = mock_entry
        result = select_field("test")
        assert result == "ONLY_FIELD"

    @patch('passkey.interactive.get_entry')
    def test_empty_fields_exits(self, mock_get):
        mock_entry = Entry(name="test", fields={})
        mock_get.return_value = mock_entry
        with pytest.raises(PasskeyError):
            select_field("test")
