"""Tests for the sharing module."""


from passkey.sharing import generate_passphrase


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
