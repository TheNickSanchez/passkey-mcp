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

    def _read_index(self) -> list:
        from passkey.keychain import _get_index_path

        path = _get_index_path()
        return json.loads(path.read_text()) if path.exists() else []

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

    def test_updates_index_for_new_entry(self, mock_keyring):
        """Adds new entry name to the file index."""
        mock_keyring.get_password.return_value = None
        entry = Entry(name="new", fields={"K": "V"})

        save_entry(entry)

        assert "new" in self._read_index()

    def test_does_not_duplicate_existing_entry(self, mock_keyring):
        """Does not add duplicate entry to the index."""
        mock_keyring.get_password.return_value = '["existing"]'
        entry = Entry(name="existing", fields={"K": "V"})

        save_entry(entry)

        assert self._read_index() == ["existing"]


class TestFileIndex:
    """Tests for the file-based entry index (P3-5)."""

    def test_migrates_legacy_keychain_index(self, mock_keyring, isolated_data_dir):
        """First read moves the keychain-held __entries__ index into entries.json."""
        mock_keyring.get_password.return_value = '["alpha", "beta"]'

        assert list_entries() == ["alpha", "beta"]

        from passkey.keychain import _get_index_path

        path = _get_index_path()
        assert path.exists()
        assert json.loads(path.read_text()) == ["alpha", "beta"]
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        # Legacy keychain item removed
        mock_keyring.delete_password.assert_called_with(SERVICE, METADATA_KEY)

    def test_index_file_wins_over_keychain(self, mock_keyring, isolated_data_dir):
        """Once the file exists, the keychain is not consulted for the index."""
        from passkey.keychain import _get_index_path

        _get_index_path().parent.mkdir(parents=True, exist_ok=True)
        _get_index_path().write_text('["file-wins"]')
        mock_keyring.get_password.return_value = '["keychain-loses"]'

        assert list_entries() == ["file-wins"]

    def test_corrupted_index_raises(self, mock_keyring, isolated_data_dir):
        from passkey.keychain import EntryCorruptedError, _get_index_path

        _get_index_path().parent.mkdir(parents=True, exist_ok=True)
        _get_index_path().write_text("{corrupted")

        with pytest.raises(EntryCorruptedError, match="corrupted"):
            list_entries()


class TestGetAllEntries:
    """P3-6: bulk reads must not spam one 'read' op per entry."""

    def test_single_bulk_read_logged(self, mock_keyring, isolated_data_dir):
        from passkey.keychain import _get_index_path, get_all_entries

        _get_index_path().parent.mkdir(parents=True, exist_ok=True)
        _get_index_path().write_text('["a", "b", "c"]')
        mock_keyring.get_password.return_value = '{"K": "V"}'

        with patch("passkey.keychain.log_operation") as mock_log:
            entries = get_all_entries()

        assert len(entries) == 3
        read_ops = [c for c in mock_log.call_args_list if c[0][0] == "read"]
        assert len(read_ops) == 1
        assert read_ops[0].kwargs["details"]["bulk"] is True
        assert read_ops[0].kwargs["details"]["count"] == 3


class TestAuditLabels:
    """Regression: creates saved with is_update=True were logged as updates."""

    def test_new_entry_logged_as_create_even_with_is_update_true(self, mock_keyring):
        mock_keyring.get_password.return_value = None  # entry is new
        entry = Entry(name="fresh", fields={"K": "V"})

        with patch("passkey.keychain.log_operation") as mock_log:
            save_entry(entry, is_update=True)

        ops = [c.kwargs.get("operation", c[0][0] if c[0] else None)
               for c in mock_log.call_args_list]
        assert "create" in ops
        assert "update" not in ops

    def test_existing_entry_logged_as_update(self, mock_keyring):
        mock_keyring.get_password.return_value = '["existing"]'
        entry = Entry(name="existing", fields={"K": "V"})

        with patch("passkey.keychain.log_operation") as mock_log:
            save_entry(entry)

        ops = [c.kwargs.get("operation", c[0][0] if c[0] else None)
               for c in mock_log.call_args_list]
        assert "update" in ops
        assert "create" not in ops


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
        # (migration may also delete the legacy __entries__ item; use any_call)
        mock_keyring.delete_password.assert_any_call(SERVICE, "test")

    def test_updates_index_after_delete(self, mock_keyring):
        """Removes entry from the file index."""
        mock_keyring.get_password.return_value = '["test", "other"]'

        delete_entry("test")

        from passkey.keychain import _get_index_path

        saved_index = json.loads(_get_index_path().read_text())
        assert "test" not in saved_index
        assert "other" in saved_index

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
