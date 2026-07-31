"""Tests for the sharing module."""

from unittest.mock import patch

from passkey.sharing import cmd_receive, generate_passphrase


class TestGeneratePassphrase:
    def test_default_length(self):
        phrase = generate_passphrase()
        words = phrase.split("-")
        assert len(words) == 8  # default is now 8 words (~64 bits entropy)

    def test_custom_length(self):
        phrase = generate_passphrase(6)
        words = phrase.split("-")
        assert len(words) == 6

    def test_words_are_from_list(self):
        from passkey.sharing import _PASSPHRASE_WORDS
        phrase = generate_passphrase()
        for word in phrase.split("-"):
            assert word in _PASSPHRASE_WORDS

    def test_uniqueness(self):
        phrases = {generate_passphrase() for _ in range(20)}
        assert len(phrases) == 20

    def test_format(self):
        phrase = generate_passphrase()
        assert all(c.isalpha() or c == "-" for c in phrase)
        assert not phrase.startswith("-")
        assert not phrase.endswith("-")


class TestWordlist:
    def test_has_at_least_256_words(self):
        from passkey.sharing import _PASSPHRASE_WORDS
        assert len(_PASSPHRASE_WORDS) >= 256

    def test_all_lowercase(self):
        from passkey.sharing import _PASSPHRASE_WORDS
        for word in _PASSPHRASE_WORDS:
            assert word.islower()

    def test_no_duplicates(self):
        from passkey.sharing import _PASSPHRASE_WORDS
        assert len(_PASSPHRASE_WORDS) == len(set(_PASSPHRASE_WORDS))


class TestReceive:
    def test_no_double_bundle_import_log(self, tmp_path):
        """Regression: receive logged bundle_import twice (inner + outer)."""
        bundle = tmp_path / "shared.enc"
        bundle.write_bytes(b"PK01" + b"\x00" * 40)

        with patch("passkey.sharing.import_bundle",
                   return_value={"created": 1, "updated": 0, "skipped": 0}), \
             patch("passkey.sharing.log_operation") as mock_log, \
             patch("getpass.getpass", return_value="x" * 12):
            cmd_receive(str(bundle))

        # import_bundle logs bundle_import itself; cmd_receive must not add another
        mock_log.assert_not_called()
