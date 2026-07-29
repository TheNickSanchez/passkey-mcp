"""Tests for the password generator."""

import string

from passkey.generator import generate_password


class TestGeneratePassword:
    def test_default_length(self):
        password = generate_password()
        assert len(password) == 32

    def test_custom_length(self):
        password = generate_password(64)
        assert len(password) == 64

    def test_minimum_length(self):
        password = generate_password(4)
        assert len(password) == 4

    def test_below_minimum_raises(self):
        try:
            generate_password(3)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "at least 4" in str(e)

    def test_contains_lowercase(self):
        password = generate_password()
        assert any(c in string.ascii_lowercase for c in password)

    def test_contains_uppercase(self):
        password = generate_password()
        assert any(c in string.ascii_uppercase for c in password)

    def test_contains_digit(self):
        password = generate_password()
        assert any(c in string.digits for c in password)

    def test_contains_symbol(self):
        password = generate_password()
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        assert any(c in symbols for c in password)

    def test_all_chars_valid(self):
        password = generate_password()
        valid = set(string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?")
        assert all(c in valid for c in password)

    def test_uniqueness(self):
        passwords = {generate_password() for _ in range(10)}
        assert len(passwords) == 10
