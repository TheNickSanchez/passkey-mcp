"""Tests for Wave 3 out-of-band LAContext auth, entry policies, and HMAC-signed leases."""

import json
import sys
import time
from unittest.mock import patch

import pytest

from passkey.auth import _authenticate_macOS
from passkey.commands import cmd_policy
from passkey.keychain import PasskeyError, get_entry, save_entry
from passkey.leases import (
    consume_lease,
    get_leases_path,
    grant_lease,
    list_leases,
    parse_ttl,
    revoke_lease,
)
from passkey.models import Entry
from passkey.runner import run_with_secrets


class TestMacOSLAContextFallback:
    """Tests for LAContext preference and sudo -v fallback when LAContext is unavailable."""

    def test_uses_lacontext_when_enabled_and_available(self, monkeypatch):
        monkeypatch.setenv("PASSKEY_DISABLE_LACONTEXT", "0")
        with (
            patch("passkey.auth._evaluate_lacontext", return_value=True) as mock_la,
            patch("passkey.auth.subprocess.run") as mock_sudo,
        ):
            assert _authenticate_macOS("Approve prod deploy") is True
        mock_la.assert_called_once_with("Approve prod deploy")
        mock_sudo.assert_not_called()

    def test_falls_back_to_sudo_when_lacontext_returns_none(self, monkeypatch):
        monkeypatch.setenv("PASSKEY_DISABLE_LACONTEXT", "0")
        with (
            patch("passkey.auth._evaluate_lacontext", return_value=None),
            patch("passkey.auth.subprocess.run") as mock_sudo,
        ):
            mock_sudo.return_value.returncode = 0
            assert _authenticate_macOS("Approve prod deploy") is True
        mock_sudo.assert_called_once()


class TestEntryPolicyAndScopedLeases:
    """Tests for Entry.policy, HMAC-signed leases.json, TTL/max-uses, and runner enforcement."""

    def test_policy_roundtrip_and_cmd_policy(self, capsys):
        save_entry(Entry(name="prod_aws", fields={"AWS_SECRET_ACCESS_KEY": "secret1234"}))
        entry = get_entry("prod_aws")
        assert entry is not None
        assert entry.policy == "allow"

        cmd_policy(entry, "prompt")
        reloaded = get_entry("prod_aws")
        assert reloaded is not None
        assert reloaded.policy == "prompt"

        cmd_policy(reloaded, None)
        assert "policy = prompt" in capsys.readouterr().out

    def test_parse_ttl_variants_and_bounds(self):
        assert parse_ttl("30s") == 30
        assert parse_ttl("15m") == 900
        assert parse_ttl("2h") == 7200
        assert parse_ttl("1d") == 86400
        assert parse_ttl(120) == 120
        with pytest.raises(PasskeyError):
            parse_ttl("0s")
        with pytest.raises(PasskeyError):
            parse_ttl("99d")

    def test_lease_max_uses_and_ttl_expiry(self, monkeypatch):
        save_entry(Entry(name="vault_prod", fields={"TOKEN": "tok_123456"}, policy="prompt"))

        grant_lease("vault_prod", ttl="10m", max_uses=2)
        leases_path = get_leases_path()
        assert oct(leases_path.stat().st_mode & 0o777) == "0o600"
        assert len(list_leases()) == 1

        assert consume_lease("vault_prod") is True
        assert list_leases()[0]["remaining_uses"] == 1

        assert consume_lease("vault_prod") is True
        # Exhausted after 2 uses
        assert list_leases() == []
        assert consume_lease("vault_prod") is False

        # TTL expiration check
        now = time.time()
        grant_lease("vault_prod", ttl="5s")
        monkeypatch.setattr(time, "time", lambda: now + 10.0)
        assert list_leases() == []
        assert consume_lease("vault_prod") is False

    def test_tampered_leases_json_rejected_by_hmac(self):
        save_entry(Entry(name="db_prod", fields={"PASS": "secret_pass"}, policy="prompt"))
        grant_lease("db_prod", ttl="15m", max_uses=1)

        path = get_leases_path()
        data = json.loads(path.read_text())
        # Attacker attempts to escalate remaining_uses without knowing __lease_hmac_key__
        data["leases"]["db_prod"]["remaining_uses"] = 9999
        path.write_text(json.dumps(data))

        with pytest.raises(PasskeyError, match="HMAC mismatch"):
            consume_lease("db_prod")

    def test_runner_enforces_prompt_policy_with_lease_and_biometric_fallback(self):
        save_entry(Entry(name="k8s_prod", fields={"KUBE_TOKEN": "kube_secret_999"}, policy="prompt"))

        # Without lease and biometric denied -> raises PasskeyError
        with (
            patch("passkey.auth.authenticate", return_value=False) as mock_auth,
            pytest.raises(PasskeyError, match="Access denied"),
        ):
            run_with_secrets(["k8s_prod"], [sys.executable, "-c", "pass"], quiet=True)
        mock_auth.assert_called_once()

        # With active 1-use lease -> succeeds without prompting auth
        grant_lease("k8s_prod", ttl="5m", max_uses=1)
        with patch("passkey.auth.authenticate", return_value=False) as mock_auth_2:
            rc = run_with_secrets(["k8s_prod"], [sys.executable, "-c", "pass"], quiet=True)
        assert rc == 0
        mock_auth_2.assert_not_called()

        # Revoke works cleanly
        grant_lease("k8s_prod", ttl="5m")
        assert revoke_lease("k8s_prod") == 1
        assert list_leases() == []
