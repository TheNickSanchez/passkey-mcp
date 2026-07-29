"""Cryptographically secure password generator for passkey."""

import secrets
import string


def generate_password(length: int = 32) -> str:
    """Generate a cryptographically secure password.

    Guarantees at least one character from each class:
    lowercase, uppercase, digit, and symbol.

    Args:
        length: Password length (minimum 4)

    Returns:
        Generated password string

    Raises:
        ValueError: If length < 4
    """
    if length < 4:
        raise ValueError(f"Password length must be at least 4, got {length}")

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Pre-fill one char from each required class
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"),
    ]

    # Fill the rest
    for _ in range(length - 4):
        password_chars.append(secrets.choice(alphabet))

    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)
