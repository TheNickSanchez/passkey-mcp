"""Shared pytest fixtures: hermetic data dir, fast crypto, no OS auth.

These autouse fixtures guarantee the suite never touches real user state
(~/Library/Application Support/passkey, ~/.config/passkey, the real audit
log) and never invokes real OS authentication (sudo/pkexec/UAC).
"""

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Redirect all passkey data to a per-test temp dir."""
    data_dir = tmp_path / "passkey-data"
    monkeypatch.setenv("PASSKEY_DATA_DIR", str(data_dir))
    monkeypatch.delenv("PASSKEY_AUDIT_LOG", raising=False)
    # Never migrate real legacy data into the test dir
    monkeypatch.setattr("passkey.dirs.get_legacy_data_dir", lambda: tmp_path / "no-legacy")
    yield data_dir


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
