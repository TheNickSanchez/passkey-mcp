"""Shared pytest fixtures: hermetic data dir, fast crypto, no OS auth.

These autouse fixtures guarantee the suite never touches real user state
(~/Library/Application Support/passkey, ~/.config/passkey, the real audit
log) and never invokes real OS authentication (sudo/pkexec/UAC).
"""

from unittest.mock import patch

import keyring
import keyring.backend
import pytest


class _InMemoryKeyring(keyring.backend.KeyringBackend):
    """Hermetic in-memory keyring so no test can ever touch the real OS keychain."""

    priority = 1

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self._store:
            from keyring.errors import PasswordDeleteError

            raise PasswordDeleteError(f"No password for ({service}, {username})")
        del self._store[(service, username)]


@pytest.fixture(autouse=True)
def isolated_keyring():
    """Replace the process keyring backend with a fresh per-test in-memory store."""
    prev = keyring.get_keyring()
    mem = _InMemoryKeyring()
    keyring.set_keyring(mem)
    try:
        yield mem
    finally:
        keyring.set_keyring(prev)


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Redirect all passkey data to a per-test temp dir."""
    from passkey.interactive import _HEADLESS_AGENT_ENV_VARS, set_no_input

    data_dir = tmp_path / "passkey-data"
    monkeypatch.setenv("PASSKEY_DATA_DIR", str(data_dir))
    monkeypatch.delenv("PASSKEY_AUDIT_LOG", raising=False)
    monkeypatch.setenv("PASSKEY_DISABLE_LACONTEXT", "1")
    for env_var in _HEADLESS_AGENT_ENV_VARS:
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.delenv("PASSKEY_ALLOW_INTERACTIVE", raising=False)
    monkeypatch.delenv("PASSKEY_OUTPUT", raising=False)
    set_no_input(False)
    # Never migrate real legacy data into the test dir
    monkeypatch.setattr("passkey.dirs.get_legacy_data_dir", lambda: tmp_path / "no-legacy")
    yield data_dir
    set_no_input(False)


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    """Defang scrypt for tests: 2^14 instead of the production 2^20."""
    monkeypatch.setattr("passkey.bundle.SCRYPT_N", 2**14)


@pytest.fixture(autouse=True)
def no_os_auth():
    """Never invoke real OS authentication from the CLI layer in tests.

    Deliberately does NOT patch passkey.auth itself — tests/test_auth.py
    covers that module with its own subprocess mocks. Yields the patcher
    so tests that exercise the real gate can call ``no_os_auth.stop()``
    (teardown tolerates the double-stop).
    """
    patcher = patch("passkey.cli._require_auth")
    patcher.start()
    yield patcher
    patcher.stop()
