"""Tests for passkey CLI."""

import sys
from unittest.mock import patch

import pytest

from passkey.cli import create_parser, main
from passkey.models import Entry


@pytest.fixture
def mock_keychain():
    """Mock keychain module functions."""
    with patch("passkey.commands.get_all_entries") as mock_all, \
         patch("passkey.commands.list_entries") as mock_list, \
         patch("passkey.commands.get_entry") as mock_get, \
         patch("passkey.commands.save_entry") as mock_save, \
         patch("passkey.commands.delete_entry") as mock_delete, \
         patch("passkey.keychain.get_entry") as mock_get_keychain, \
         patch("passkey.dirs.run_migration_if_needed"):
        mock_get_keychain.side_effect = lambda name: mock_get.return_value
        yield {
            "all": mock_all,
            "list": mock_list,
            "get": mock_get,
            "save": mock_save,
            "delete": mock_delete,
        }


class TestListCommand:
    """Tests for 'list' subcommand."""

    def test_list_shows_entries(self, mock_keychain, capsys):
        """list displays entry names."""
        mock_keychain["all"].return_value = [
            Entry(name="slack", fields={"T": "v"}),
            Entry(name="jamf", fields={"T": "v"}),
        ]

        with patch.object(sys, "argv", ["passkey", "list"]):
            main()

        captured = capsys.readouterr()
        assert "jamf" in captured.out
        assert "slack" in captured.out

    def test_list_empty_message(self, mock_keychain, capsys):
        """list shows message when no entries."""
        mock_keychain["all"].return_value = []

        with patch.object(sys, "argv", ["passkey", "list"]):
            main()

        captured = capsys.readouterr()
        assert "No entries found" in captured.out

    def test_list_sorted_alphabetically(self, mock_keychain, capsys):
        """list displays entries in alphabetical order."""
        mock_keychain["all"].return_value = [
            Entry(name="zebra", fields={"T": "v"}),
            Entry(name="apple", fields={"T": "v"}),
            Entry(name="mango", fields={"T": "v"}),
        ]

        with patch.object(sys, "argv", ["passkey", "list"]):
            main()

        captured = capsys.readouterr()
        lines = [line.split()[0] for line in captured.out.strip().split("\n") if line.strip()]
        assert lines == ["apple", "mango", "zebra"]


class TestInfoCommand:
    """Tests for 'info' subcommand."""

    def test_info_shows_metadata_and_fields(self, mock_keychain, capsys):
        """info displays entry metadata and field names."""
        mock_keychain["get"].return_value = Entry(
            name="test",
            fields={"TOKEN": "secret", "COOKIE": "value"},
            created="2024-01-15T10:30:00",
            modified="2024-01-20T14:22:00",
            source="import-mcp"
        )

        with patch.object(sys, "argv", ["passkey", "info", "test"]):
            main()

        captured = capsys.readouterr()
        assert "Entry: test" in captured.out
        assert "2024-01-15" in captured.out
        assert "2024-01-20" in captured.out
        assert "import-mcp" in captured.out
        assert "TOKEN" in captured.out
        assert "COOKIE" in captured.out
        assert "secret" not in captured.out
        assert "value" not in captured.out

    def test_info_entry_not_found(self, mock_keychain, capsys):
        """info shows error for missing entry."""
        mock_keychain["get"].return_value = None

        with patch.object(sys, "argv", ["passkey", "info", "missing"]), \
             patch("passkey.interactive.select_entry", return_value="missing"), \
             pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err


class TestGetCommand:
    """Tests for 'get' subcommand."""

    def test_get_all_copies_key_value_pairs(self, mock_keychain, capsys):
        """get --all copies all fields as key:value pairs."""
        mock_keychain["get"].return_value = Entry(
            name="test",
            fields={"A": "1", "B": "2"}
        )

        with patch.object(sys, "argv", ["passkey", "get", "test", "--all"]), \
             patch("passkey.commands.copy_with_autoclear") as mock_copy:
            main()

        mock_copy.assert_called_once()
        call_arg = mock_copy.call_args[0][0]
        assert "A:1" in call_arg
        assert "B:2" in call_arg


class TestPositionalFallback:
    """Tests for positional fallback: passkey <entry>."""

    def test_positional_entry_triggers_get_interactive(self, mock_keychain, capsys):
        """passkey <entry> falls back to get-interactive."""
        entry = Entry(name="slack", fields={"TOKEN": "secret"})
        mock_keychain["get"].return_value = entry

        with patch.object(sys, "argv", ["passkey", "slack"]), \
             patch("passkey.commands.cmd_get_interactive") as mock_interactive:
            main()

        mock_interactive.assert_called_once_with(entry)

    def test_unknown_entry_falls_to_error(self, mock_keychain, capsys):
        """passkey <unknown> with no match in non-interactive session exits 1."""
        mock_keychain["get"].return_value = None

        with patch.object(sys, "argv", ["passkey", "doesnotexist"]), \
             patch("passkey.interactive.is_interactive", return_value=False), \
             pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1


class TestParserSubcommands:
    """Tests for argument parser subcommands."""

    def test_subcommands_exist(self):
        """Parser has all required subcommands."""
        parser = create_parser()
        help_text = parser.format_help()
        for cmd in ("new", "list", "get", "edit", "delete", "info", "run"):
            assert cmd in help_text

    def test_export_subcommand_exists(self):
        """Parser has export subcommand."""
        parser = create_parser()
        help_text = parser.format_help()
        assert "export" in help_text

    def test_get_parses_entry_arg(self):
        """get subcommand parses entry argument."""
        parser = create_parser()
        args = parser.parse_args(["get", "myentry"])
        assert args.command == "get"
        assert args.entry == "myentry"

    def test_get_all_flag(self):
        """get --all flag is parsed correctly."""
        parser = create_parser()
        args = parser.parse_args(["get", "myentry", "--all"])
        assert args.get_all is True

    def test_set_field_parses_entry_and_field(self):
        """set-field parses entry and field (value prompted separately)."""
        parser = create_parser()
        args = parser.parse_args(["set-field", "myentry", "myfield"])
        assert args.command == "set-field"
        assert args.entry == "myentry"
        assert args.field == "myfield"

    def test_delete_parses_entry(self):
        """delete subcommand parses entry argument."""
        parser = create_parser()
        args = parser.parse_args(["delete", "myentry"])
        assert args.command == "delete"
        assert args.entry == "myentry"
