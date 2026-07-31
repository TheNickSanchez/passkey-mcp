"""Tests for passkey.commands entry handlers."""

from unittest.mock import patch

from passkey.commands import cmd_set_field
from passkey.models import Entry


class TestSetField:
    """Regression: cmd_set_field rebuilt the Entry and wiped config/created/source."""

    def test_preserves_config_created_source(self):
        entry = Entry(
            name="svc",
            fields={"OLD": "1"},
            config={"HOST": "example.com"},
            created="2024-01-01T00:00:00",
            source="import-mcp",
        )
        with patch("passkey.commands.save_entry") as mock_save:
            cmd_set_field(entry, "NEW", "2")

        mock_save.assert_called_once()
        saved = mock_save.call_args[0][0]
        assert saved.fields == {"OLD": "1", "NEW": "2"}
        assert saved.config == {"HOST": "example.com"}
        assert saved.created == "2024-01-01T00:00:00"
        assert saved.source == "import-mcp"
        assert mock_save.call_args.kwargs["is_update"] is True

    def test_updates_existing_field_in_place(self):
        entry = Entry(
            name="svc",
            fields={"TOKEN": "old"},
            config={"HOST": "h"},
            created="2024-01-01T00:00:00",
        )
        with patch("passkey.commands.save_entry") as mock_save:
            cmd_set_field(entry, "TOKEN", "new")

        saved = mock_save.call_args[0][0]
        assert saved.fields == {"TOKEN": "new"}
        assert saved.config == {"HOST": "h"}
        assert saved.created == "2024-01-01T00:00:00"
