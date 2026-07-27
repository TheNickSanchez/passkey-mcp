"""Tests for passkey.bundle module."""

from unittest.mock import patch

import pytest

from passkey.bundle import (
    FORMAT_VERSION,
    MAGIC,
    NONCE_LEN,
    SALT_LEN,
    _derive_key,
    export_bundle,
    import_bundle,
)
from passkey.keychain import PasskeyError
from passkey.models import Entry


class TestDeriveKey:
    def test_deterministic(self):
        salt = b"\x00" * 32
        key1 = _derive_key("test-passphrase", salt)
        key2 = _derive_key("test-passphrase", salt)
        assert key1 == key2
        assert len(key1) == 32

    def test_different_salt_different_key(self):
        key1 = _derive_key("test-passphrase", b"\x00" * 32)
        key2 = _derive_key("test-passphrase", b"\x01" * 32)
        assert key1 != key2

    def test_different_passphrase_different_key(self):
        salt = b"\x00" * 32
        key1 = _derive_key("passphrase-one", salt)
        key2 = _derive_key("passphrase-two", salt)
        assert key1 != key2


class TestExportBundle:
    @patch("passkey.bundle.log_operation")
    @patch("passkey.bundle.get_entry")
    @patch("passkey.bundle.list_entries")
    def test_export_creates_file(self, mock_list, mock_get, mock_log, tmp_path):
        mock_list.return_value = ["test-entry"]
        mock_get.return_value = Entry(
            name="test-entry", fields={"TOKEN": "secret123"}
        )
        output = tmp_path / "test.enc"
        result = export_bundle(str(output), passphrase="a-long-passphrase")
        assert result == output
        assert output.exists()
        assert oct(output.stat().st_mode & 0o777) == "0o600"

    @patch("passkey.bundle.log_operation")
    @patch("passkey.bundle.get_entry")
    @patch("passkey.bundle.list_entries")
    def test_export_file_format(self, mock_list, mock_get, mock_log, tmp_path):
        mock_list.return_value = ["myentry"]
        mock_get.return_value = Entry(name="myentry", fields={"K": "V"})
        output = tmp_path / "test.enc"
        export_bundle(str(output), passphrase="a-long-passphrase")

        data = output.read_bytes()
        assert data[:4] == MAGIC
        import struct
        version = struct.unpack(">I", data[4:8])[0]
        assert version == FORMAT_VERSION
        assert len(data) > 8 + SALT_LEN + NONCE_LEN + 16

    @patch("passkey.bundle.list_entries")
    def test_export_fails_no_entries(self, mock_list, tmp_path):
        mock_list.return_value = []
        with pytest.raises(PasskeyError, match="No entries to export"):
            export_bundle(str(tmp_path / "out.enc"), passphrase="a-long-passphrase")

    @patch("passkey.bundle.list_entries")
    def test_export_fails_missing_entries(self, mock_list, tmp_path):
        mock_list.return_value = ["exists"]
        with pytest.raises(PasskeyError, match="not found"):
            export_bundle(
                str(tmp_path / "out.enc"),
                entry_names=["missing"],
                passphrase="a-long-passphrase",
            )

    @patch("passkey.bundle.get_entry")
    @patch("passkey.bundle.list_entries")
    def test_export_fails_file_exists(self, mock_list, mock_get, tmp_path):
        mock_list.return_value = ["e"]
        mock_get.return_value = Entry(name="e", fields={"K": "V"})
        output = tmp_path / "exists.enc"
        output.write_text("existing")
        with pytest.raises(FileExistsError):
            export_bundle(str(output), passphrase="a-long-passphrase")

    @patch("passkey.bundle.get_entry")
    @patch("passkey.bundle.list_entries")
    def test_export_fails_short_passphrase(self, mock_list, mock_get, tmp_path):
        mock_list.return_value = ["e"]
        mock_get.return_value = Entry(name="e", fields={"K": "V"})
        with pytest.raises(PasskeyError, match="at least"):
            export_bundle(str(tmp_path / "out.enc"), passphrase="short")


class TestImportBundle:
    def _make_bundle(self, tmp_path, entries, passphrase="a-long-passphrase"):
        """Helper to create a test bundle via export."""
        output = tmp_path / "test.enc"
        with patch("passkey.bundle.list_entries") as mock_list, \
             patch("passkey.bundle.get_entry") as mock_get, \
             patch("passkey.bundle.log_operation"):
            mock_list.return_value = [e.name for e in entries]
            mock_get.side_effect = lambda name: next(
                (e for e in entries if e.name == name), None
            )
            export_bundle(str(output), passphrase=passphrase)
        return output

    @patch("passkey.bundle.log_operation")
    @patch("passkey.bundle.save_entry")
    @patch("passkey.bundle.get_entry")
    def test_roundtrip(self, mock_get_import, mock_save, mock_log, tmp_path):
        entries = [Entry(name="roundtrip", fields={"SECRET": "value123"})]
        bundle_path = self._make_bundle(tmp_path, entries)

        mock_get_import.return_value = None
        result = import_bundle(str(bundle_path), passphrase="a-long-passphrase")
        assert result["created"] == 1
        assert result["skipped"] == 0
        mock_save.assert_called_once()
        saved_entry = mock_save.call_args[0][0]
        assert saved_entry.name == "roundtrip"
        assert saved_entry.fields == {"SECRET": "value123"}

    @patch("passkey.bundle.log_operation")
    @patch("passkey.bundle.save_entry")
    @patch("passkey.bundle.get_entry")
    def test_wrong_passphrase(self, mock_get, mock_save, mock_log, tmp_path):
        entries = [Entry(name="test", fields={"K": "V"})]
        bundle_path = self._make_bundle(tmp_path, entries, passphrase="correct-passphrase")

        with pytest.raises(PasskeyError, match="wrong passphrase"):
            import_bundle(str(bundle_path), passphrase="wrong-passphrase!")

    @patch("passkey.bundle.log_operation")
    @patch("passkey.bundle.save_entry")
    @patch("passkey.bundle.get_entry")
    def test_skip_existing(self, mock_get, mock_save, mock_log, tmp_path):
        entries = [Entry(name="existing", fields={"K": "V"})]
        bundle_path = self._make_bundle(tmp_path, entries)

        mock_get.return_value = Entry(name="existing", fields={"OLD": "val"})
        result = import_bundle(str(bundle_path), passphrase="a-long-passphrase", mode="skip")
        assert result["skipped"] == 1
        assert result["created"] == 0
        mock_save.assert_not_called()

    @patch("passkey.bundle.log_operation")
    @patch("passkey.bundle.save_entry")
    @patch("passkey.bundle.get_entry")
    def test_overwrite_existing(self, mock_get, mock_save, mock_log, tmp_path):
        entries = [Entry(name="existing", fields={"NEW": "val"})]
        bundle_path = self._make_bundle(tmp_path, entries)

        mock_get.return_value = Entry(name="existing", fields={"OLD": "val"})
        result = import_bundle(str(bundle_path), passphrase="a-long-passphrase", mode="overwrite")
        assert result["updated"] == 1
        mock_save.assert_called_once()

    def test_import_nonexistent_file(self):
        with pytest.raises(PasskeyError, match="not found"):
            import_bundle("/nonexistent/path.enc", passphrase="a-long-passphrase")

    def test_import_invalid_magic(self, tmp_path):
        bad_file = tmp_path / "bad.enc"
        bad_file.write_bytes(b"XXXX" + b"\x00" * 100)
        with pytest.raises(PasskeyError, match="bad magic"):
            import_bundle(str(bad_file), passphrase="a-long-passphrase")

    def test_import_too_small(self, tmp_path):
        tiny_file = tmp_path / "tiny.enc"
        tiny_file.write_bytes(b"PK01")
        with pytest.raises(PasskeyError, match="too small"):
            import_bundle(str(tiny_file), passphrase="a-long-passphrase")

    @patch("passkey.bundle.log_operation")
    @patch("passkey.bundle.save_entry")
    @patch("passkey.bundle.get_entry")
    def test_multiple_entries(self, mock_get, mock_save, mock_log, tmp_path):
        entries = [
            Entry(name="entry-one", fields={"A": "1"}),
            Entry(name="entry-two", fields={"B": "2"}),
            Entry(name="entry-three", fields={"C": "3"}),
        ]
        bundle_path = self._make_bundle(tmp_path, entries)

        mock_get.return_value = None
        result = import_bundle(str(bundle_path), passphrase="a-long-passphrase")
        assert result["created"] == 3
        assert mock_save.call_count == 3

    def test_import_tampered_data(self, tmp_path):
        """Tampered ciphertext should fail GCM authentication."""
        entries = [Entry(name="test", fields={"K": "V"})]
        bundle_path = self._make_bundle(tmp_path, entries)

        data = bytearray(bundle_path.read_bytes())
        data[-5] ^= 0xFF
        bundle_path.write_bytes(bytes(data))

        with pytest.raises(PasskeyError, match="wrong passphrase|corrupted"):
            import_bundle(str(bundle_path), passphrase="a-long-passphrase")
