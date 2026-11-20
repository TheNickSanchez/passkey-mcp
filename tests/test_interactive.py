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


class TestQuestionaryCancelSentinelRegressions:
    """End-to-end prompt_toolkit pipe tests exercising real questionary.Choice and .ask()."""

    @staticmethod
    def _run_with_pipe_keys(keystrokes: str, fn):
        import questionary
        from prompt_toolkit.input import create_pipe_input
        from prompt_toolkit.output import DummyOutput

        real_select = questionary.select
        with create_pipe_input() as pipe_in:
            pipe_in.send_text(keystrokes)

            def _select_with_pipe(*args, **kwargs):
                kwargs.setdefault("input", pipe_in)
                kwargs.setdefault("output", DummyOutput())
                return real_select(*args, **kwargs)

            with patch.object(questionary, "select", side_effect=_select_with_pipe):
                return fn()

    def test_cmd_get_interactive_cancel_copy_all_and_field_selection(self, capsys):
        from passkey.commands import cmd_get_interactive

        entry = Entry(
            name="stripe",
            fields={"API_KEY": "sk_live_1234", "WEBHOOK_SECRET": "whsec_5678"},
        )

        with patch("passkey.interactive.is_interactive", return_value=True):
            # 1. Selecting "(cancel)" (index 3: 2 fields + Copy all + (cancel); Separator skipped)
            with patch("passkey.commands.copy_with_autoclear") as mock_copy:
                self._run_with_pipe_keys(
                    "\x1b[B\x1b[B\x1b[B\r", lambda: cmd_get_interactive(entry)
                )
            mock_copy.assert_not_called()

            # 2. Selecting "Copy all fields (KEY='value')" (index 2: 2 Downs + Enter)
            with patch("passkey.commands.copy_with_autoclear") as mock_copy_all:
                self._run_with_pipe_keys(
                    "\x1b[B\x1b[B\r", lambda: cmd_get_interactive(entry)
                )
            mock_copy_all.assert_called_once_with(
                "API_KEY='sk_live_1234'\nWEBHOOK_SECRET='whsec_5678'",
                timeout_seconds=30,
            )

            # 3. Selecting an actual field (index 0: Enter)
            with patch("passkey.commands.copy_with_autoclear") as mock_copy_one:
                self._run_with_pipe_keys("\r", lambda: cmd_get_interactive(entry))
            mock_copy_one.assert_called_once_with("sk_live_1234", timeout_seconds=30)
            capsys.readouterr()

    def test_cmd_get_interactive_sentinel_collision_safety(self, capsys):
        """Fields literally named '__all__' or '(cancel)' must not collide with menu sentinels."""
        from passkey.commands import cmd_get_interactive

        tricky = Entry(
            name="tricky",
            fields={"A": "val_a", "__all__": "val_dunder_all", "(cancel)": "val_literal_cancel"},
        )

        with patch("passkey.interactive.is_interactive", return_value=True):
            # Real field "__all__" (1 Down + Enter) copies its value instead of triggering Copy all
            with patch("passkey.commands.copy_with_autoclear") as mock_copy_dunder:
                self._run_with_pipe_keys("\x1b[B\r", lambda: cmd_get_interactive(tricky))
            mock_copy_dunder.assert_called_once_with("val_dunder_all", timeout_seconds=30)

            # Real field "(cancel)" (2 Downs + Enter) copies its value instead of cancelling
            with patch("passkey.commands.copy_with_autoclear") as mock_copy_lit:
                self._run_with_pipe_keys("\x1b[B\x1b[B\r", lambda: cmd_get_interactive(tricky))
            mock_copy_lit.assert_called_once_with("val_literal_cancel", timeout_seconds=30)

            # Bottom menu "(cancel)" (4 Downs + Enter) cancels cleanly with zero clipboard writes
            with patch("passkey.commands.copy_with_autoclear") as mock_copy_none:
                self._run_with_pipe_keys(
                    "\x1b[B\x1b[B\x1b[B\x1b[B\r", lambda: cmd_get_interactive(tricky)
                )
            mock_copy_none.assert_not_called()
            capsys.readouterr()

    def test_select_entry_and_select_field_allow_empty_cancel_returns_none(self):
        from passkey.keychain import save_entry

        save_entry(Entry(name="alpha", fields={"KEY_1": "v1", "KEY_2": "v2"}))
        save_entry(Entry(name="beta", fields={"KEY_B": "vb"}))

        with patch("passkey.interactive.is_interactive", return_value=True):
            # 2 entries + (cancel) -> 2 Downs + Enter selects (cancel) and returns None
            chosen_entry = self._run_with_pipe_keys(
                "\x1b[B\x1b[B\r", lambda: select_entry(allow_empty=True)
            )
            assert chosen_entry is None

            # 2 fields + (cancel) -> 2 Downs + Enter selects (cancel) and returns None
            chosen_field = self._run_with_pipe_keys(
                "\x1b[B\x1b[B\r", lambda: select_field("alpha", allow_empty=True)
            )
            assert chosen_field is None

    def test_cmd_rotate_cancel_exits_cleanly_without_rotating_or_saving(self, capsys):
        from passkey.health import cmd_rotate
        from passkey.keychain import get_entry, save_entry

        save_entry(Entry(name="rot_multi", fields={"KEY_1": "sec1", "KEY_2": "sec2"}))
        assert get_entry("rot_multi").last_rotated is None

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("passkey.interactive.prompt_secret") as mock_prompt,
            patch("passkey.keychain.save_entry") as mock_save,
        ):
            self._run_with_pipe_keys(
                "\x1b[B\x1b[B\r", lambda: cmd_rotate("rot_multi")
            )

        out = capsys.readouterr().out
        assert "Cancelled" in out
        mock_prompt.assert_not_called()
        mock_save.assert_not_called()
        reloaded = get_entry("rot_multi")
        assert reloaded is not None
        assert reloaded.last_rotated is None
        assert reloaded.fields == {"KEY_1": "sec1", "KEY_2": "sec2"}
