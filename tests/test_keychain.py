"""Tests for passkey.keychain module."""

import json
from unittest.mock import patch

import pytest

from passkey.keychain import (
    METADATA_KEY,
    SERVICE,
    delete_entry,
    get_entry,
    list_entries,
    save_entry,
)
from passkey.models import Entry


@pytest.fixture
def mock_keyring():
    """Mock keyring module."""
    with patch("passkey.keychain.keyring") as mock:
        mock.get_password.return_value = None
        yield mock


class TestListEntries:
    """Tests for list_entries()."""

    def test_returns_empty_when_no_metadata(self, mock_keyring):
        """Returns empty list when no entries exist."""
        mock_keyring.get_password.return_value = None
        assert list_entries() == []

    def test_returns_parsed_list(self, mock_keyring):
        """Returns list from metadata JSON."""
        mock_keyring.get_password.return_value = '["slack", "jamf"]'
        assert list_entries() == ["slack", "jamf"]

    def test_returns_empty_for_empty_string(self, mock_keyring):
        """Returns empty list for empty string."""
        mock_keyring.get_password.return_value = ""
        assert list_entries() == []


class TestSaveEntry:
    """Tests for save_entry()."""

    def test_saves_entry_fields(self, mock_keyring):
        """Saves entry fields as JSON with metadata."""
        mock_keyring.get_password.return_value = None
        entry = Entry(name="test", fields={"KEY": "value"})

        save_entry(entry)

        # Verify entry was saved with correct structure
        calls = [c for c in mock_keyring.set_password.call_args_list if c[0][1] == "test"]
        assert len(calls) == 1
        saved_json = json.loads(calls[0][0][2])
        assert saved_json["fields"] == {"KEY": "value"}
        assert "_meta" in saved_json

    def test_updates_metadata_for_new_entry(self, mock_keyring):
        """Adds new entry name to metadata."""
        mock_keyring.get_password.return_value = "[]"
        entry = Entry(name="new", fields={"K": "V"})

        save_entry(entry)

        # Should save metadata with new entry name
        calls = mock_keyring.set_password.call_args_list
        metadata_call = [c for c in calls if c[0][1] == METADATA_KEY]
        assert len(metadata_call) == 1
        saved_metadata = json.loads(metadata_call[0][0][2])
        assert "new" in saved_metadata

    def test_does_not_duplicate_existing_entry(self, mock_keyring):
        """Does not add duplicate entry to metadata."""
        mock_keyring.get_password.return_value = '["existing"]'
        entry = Entry(name="existing", fields={"K": "V"})

        save_entry(entry)

        # Should save entry but not update metadata
        calls = mock_keyring.set_password.call_args_list
        metadata_calls = [c for c in calls if c[0][1] == METADATA_KEY]
        assert len(metadata_calls) == 0


class TestGetEntry:
    """Tests for get_entry()."""

    def test_returns_none_when_not_found(self, mock_keyring):
        """Returns None for non-existent entry."""
        mock_keyring.get_password.return_value = None
        assert get_entry("missing") is None

    def test_returns_entry_when_found(self, mock_keyring):
        """Returns parsed Entry when found."""
        mock_keyring.get_password.return_value = '{"TOKEN": "secret"}'
        entry = get_entry("found")
        assert entry is not None
        assert entry.name == "found"
        assert entry.fields == {"TOKEN": "secret"}

    def test_returns_none_for_empty_string(self, mock_keyring):
        """Returns None for empty string."""
        mock_keyring.get_password.return_value = ""
        assert get_entry("empty") is None


class TestDeleteEntry:
    """Tests for delete_entry()."""

    def test_deletes_from_keyring(self, mock_keyring):
        """Calls keyring.delete_password."""
        mock_keyring.get_password.return_value = '["test"]'
        delete_entry("test")
        mock_keyring.delete_password.assert_called_with(SERVICE, "test")

    def test_updates_metadata_after_delete(self, mock_keyring):
        """Removes entry from metadata list."""
        mock_keyring.get_password.return_value = '["test", "other"]'

        delete_entry("test")

        # Check metadata was updated without the deleted entry
        calls = mock_keyring.set_password.call_args_list
        metadata_call = [c for c in calls if c[0][1] == METADATA_KEY]
        assert len(metadata_call) == 1
        saved_metadata = json.loads(metadata_call[0][0][2])
        assert "test" not in saved_metadata
        assert "other" in saved_metadata

    def test_returns_false_when_not_found(self, mock_keyring):
        """Returns False when entry doesn't exist."""
        from keyring.errors import PasswordDeleteError
        mock_keyring.delete_password.side_effect = PasswordDeleteError()

        result = delete_entry("missing")

        assert result is False

    def test_returns_true_on_success(self, mock_keyring):
        """Returns True on successful delete."""
        mock_keyring.get_password.return_value = '["test"]'

        result = delete_entry("test")

        assert result is True
