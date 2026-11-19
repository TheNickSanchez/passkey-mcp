"""Tests for v0.8.0 Milestone 4: Session-scoped Touch ID policy ('session')."""

import json
import os
import sys
from unittest.mock import patch

import pytest

from passkey.cli import main
from passkey.keychain import PasskeyError, _get_entry, save_entry
from passkey.leases import (
    authorize_entry_access,
    get_leases_path,
    list_leases,
    peek_lease,
)
from passkey.mcp_server import passkey_entry_info
from passkey.models import Entry
from passkey.runner import preflight_run


class TestSessionScopedTouchIdPolicy:
    """Verify policy='session' Touch ID amortization, PID/start-time binding, and HMAC safety."""

    def test_session_policy_unlocks_once_per_agent_session_while_prompt_stays_strict(
        self, monkeypatch, capsys
    ):
        monkeypatch.setenv("CLAUDECODE", "1")
        save_entry(Entry(name="stripe", fields={"STRIPE_SECRET_KEY": "sk_test_session_123"}))
        save_entry(
            Entry(
                name="prod_root",
                fields={"ROOT_KEY": "rk_live_strict_999"},
                policy="prompt",
            )
        )

        # Configure policy=session via CLI
        with patch.object(sys, "argv", ["passkey", "policy", "stripe", "session", "--json"]):
            main()
        pol_json = json.loads(capsys.readouterr().out)
        assert pol_json == {
            "entry": "stripe",
            "policy": "session",
            "has_active_lease": False,
            "updated": True,
        }

        # Before unlock: preflight and MCP entry_info report will_prompt_biometric=True
        info_before = passkey_entry_info("stripe")
        assert info_before["policy"] == "session"
        assert info_before["has_active_lease"] is False
        assert info_before["will_prompt_biometric"] is True

        pre_before = preflight_run(["stripe"], [sys.executable, "-V"])
        assert pre_before["will_prompt_biometric"] is True
        assert pre_before["prompt_entries_without_lease"] == ["stripe"]

        stripe_entry = _get_entry("stripe", log_read=False)
        assert stripe_entry is not None

        # 1st access: prompts Touch ID with explicit 10m session reason
        with patch("passkey.auth.authenticate", return_value=True) as mock_auth_first:
            authorize_entry_access(stripe_entry)
        mock_auth_first.assert_called_once()
        reason_arg = mock_auth_first.call_args[0][0]
        assert "unlock 'stripe' for claude-code (10m session)" in reason_arg

        # Lease is now active for this session
        info_after = passkey_entry_info("stripe")
        assert info_after["has_active_lease"] is True
        assert info_after["will_prompt_biometric"] is False

        # 2nd, 3rd, and 4th accesses in same agent session: ZERO Touch ID prompts!
        with patch("passkey.auth.authenticate", return_value=False) as mock_auth_subsequent:
            authorize_entry_access(stripe_entry)
            authorize_entry_access(stripe_entry)
            authorize_entry_access(stripe_entry)
        mock_auth_subsequent.assert_not_called()

        # Meanwhile, policy='prompt' STILL prompts on every single invocation
        prod_entry = _get_entry("prod_root", log_read=False)
        assert prod_entry is not None
        with patch("passkey.auth.authenticate", return_value=True) as mock_auth_strict:
            authorize_entry_access(prod_entry)
            authorize_entry_access(prod_entry)
        assert mock_auth_strict.call_count == 2

        # Upgrading 'stripe' from 'session' -> 'prompt' must NOT accept the auto-minted session lease
        stripe_entry.policy = "prompt"
        save_entry(stripe_entry, is_update=True)
        info_upgraded = passkey_entry_info("stripe")
        assert info_upgraded["has_active_lease"] is False
        assert info_upgraded["will_prompt_biometric"] is True
        with (
            patch("passkey.auth.authenticate", return_value=False),
            pytest.raises(PasskeyError) as exc_strict,
        ):
            authorize_entry_access(stripe_entry)
        assert exc_strict.value.error_code == "BIOMETRIC_DENIED"

    def test_redteam_pid_reuse_unrelated_caller_and_hmac_tamper(self, monkeypatch):
        monkeypatch.setenv("GEMINI_CLI", "1")
        save_entry(
            Entry(
                name="github_sess",
                fields={"GITHUB_TOKEN": "ghp_session_bound_token"},
                policy="session",
            )
        )
        entry = _get_entry("github_sess", log_read=False)
        assert entry is not None

        fake_anchor = {
            "pid": os.getpid(),
            "start_time": "Wed Nov 18 22:00:00 2026",
            "client": "gemini-cli",
        }

        with (
            patch("passkey.leases.get_session_anchor", return_value=fake_anchor),
            patch("passkey.leases.get_process_start_token", return_value="Wed Nov 18 22:00:00 2026"),
            patch("passkey.leases.get_caller_ancestor_pids", return_value={os.getpid(), 1}),
            patch("passkey.auth.authenticate", return_value=True) as mock_unlock,
        ):
            authorize_entry_access(entry)
            mock_unlock.assert_called_once()
            assert peek_lease("github_sess") is not None

        # Attack A: Unrelated process (not a descendant of session_pid) tries to piggyback
        with (
            patch("passkey.leases.get_process_start_token", return_value="Wed Nov 18 22:00:00 2026"),
            patch("passkey.leases.get_caller_ancestor_pids", return_value={999991, 999992}),
            patch("passkey.auth.authenticate", return_value=False) as mock_other_proc,
        ):
            assert peek_lease("github_sess") is None
            assert list_leases() == []
            with pytest.raises(PasskeyError) as exc_other:
                authorize_entry_access(entry)
            assert exc_other.value.error_code == "BIOMETRIC_DENIED"
            mock_other_proc.assert_called_once()

        # Original caller still has its session lease intact!
        with (
            patch("passkey.leases.get_process_start_token", return_value="Wed Nov 18 22:00:00 2026"),
            patch("passkey.leases.get_caller_ancestor_pids", return_value={os.getpid(), 1}),
            patch("passkey.auth.authenticate", return_value=False) as mock_orig_ok,
        ):
            authorize_entry_access(entry)
            mock_orig_ok.assert_not_called()

        # Attack B: OS recycles PID (same session_pid, different lstart start_time token!)
        with (
            patch("passkey.leases.get_process_start_token", return_value="Wed Nov 18 23:59:59 2026"),
            patch("passkey.leases.get_caller_ancestor_pids", return_value={os.getpid(), 1}),
            patch("passkey.auth.authenticate", return_value=False) as mock_recycled,
        ):
            assert peek_lease("github_sess") is None
            with pytest.raises(PasskeyError) as exc_recycled:
                authorize_entry_access(entry)
            assert exc_recycled.value.error_code == "BIOMETRIC_DENIED"
            mock_recycled.assert_called_once()

        # Attack C: Tampering with session_pid inside leases.json fails HMAC check
        with (
            patch("passkey.leases.get_session_anchor", return_value=fake_anchor),
            patch("passkey.leases.get_process_start_token", return_value="Wed Nov 18 22:00:00 2026"),
            patch("passkey.leases.get_caller_ancestor_pids", return_value={os.getpid(), 1}),
            patch("passkey.auth.authenticate", return_value=True),
        ):
            authorize_entry_access(entry)

        leases_path = get_leases_path()
        raw_leases = json.loads(leases_path.read_text(encoding="utf-8"))
        only_key = next(iter(raw_leases["leases"]))
        raw_leases["leases"][only_key]["session_pid"] = 1
        leases_path.write_text(json.dumps(raw_leases), encoding="utf-8")

        with pytest.raises(PasskeyError, match="HMAC mismatch"):
            peek_lease("github_sess")

    def test_configurable_agent_session_lease_ttl(self, monkeypatch, capsys):
        monkeypatch.setenv("CURSOR_AGENT", "1")
        with patch.object(
            sys, "argv", ["passkey", "config", "agent-session-lease-ttl", "5m", "--json"]
        ):
            main()
        cfg_out = json.loads(capsys.readouterr().out)
        assert cfg_out == {
            "key": "agent_session_lease_ttl",
            "value": 300,
            "updated": True,
        }

        save_entry(Entry(name="vercel_sess", fields={"VERCEL_TOKEN": "vt_123"}, policy="session"))
        entry = _get_entry("vercel_sess", log_read=False)
        assert entry is not None

        with patch("passkey.auth.authenticate", return_value=True) as mock_auth:
            authorize_entry_access(entry)
        assert "(5m session)" in mock_auth.call_args[0][0]
        lease = peek_lease("vercel_sess")
        assert lease is not None
        assert lease["ttl_seconds"] == 300
