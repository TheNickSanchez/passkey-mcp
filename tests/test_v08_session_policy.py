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


class TestDefaultPolicyAndBulkModes:
    """Tests for v0.10 default-policy inheritance and passkey policy --all [--exclude-mcp]."""

    def test_default_policy_inherited_by_new_request_and_net_new_upload(
        self, monkeypatch, capsys
    ):
        from unittest.mock import MagicMock

        from passkey.commands import cmd_new
        from passkey.request_secret import request_secret
        from passkey.settings import set_setting
        from passkey.sharing import cmd_upload, encode_share_token

        set_setting("default_policy", "session")

        # 1. passkey new inherits default_policy='session'
        text_answers = iter(["API_KEY=sk_live_new_inherit_123", ""])

        def _fake_text(*args, **kwargs):
            m = MagicMock()
            m.ask.side_effect = lambda: next(text_answers)
            return m

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("questionary.text", side_effect=_fake_text),
        ):
            cmd_new(name="stripe_new")

        created_new = _get_entry("stripe_new", log_read=False)
        assert created_new is not None
        assert created_new.policy == "session"

        # 2. passkey request (when --policy is omitted) inherits default_policy on net-new entry,
        #    while preserving existing entry's policy when updating!
        monkeypatch.setattr("passkey.request_secret.sys.platform", "darwin")
        mock_proc = MagicMock(returncode=0, stdout="req_secret_val_999\n", stderr="")
        with patch("passkey.request_secret.subprocess.run", return_value=mock_proc):
            res_req = request_secret("aws_req", ["AWS_SECRET_ACCESS_KEY"], cooldown_seconds=0.0)
        assert res_req["policy"] == "session"
        assert _get_entry("aws_req", log_read=False).policy == "session"

        save_entry(Entry(name="existing_allow", fields={"K1": "v1"}, policy="allow"))
        with patch("passkey.request_secret.subprocess.run", return_value=mock_proc):
            res_upd = request_secret("existing_allow", ["K2"], cooldown_seconds=0.0)
        assert res_upd["policy"] == "allow"
        assert _get_entry("existing_allow", log_read=False).policy == "allow"

        # 3. passkey upload: net-new entry with default 'allow' inherits default_policy ('session'),
        #    whereas sender's stricter 'prompt' policy is preserved!
        tok_allow = encode_share_token(
            Entry(name="shared_default", fields={"TOKEN": "tok_allow_123"}, policy="allow"),
            passphrase=None,
        )
        with patch("passkey.interactive.prompt_secret", return_value=tok_allow):
            cmd_upload()
        uploaded_default = _get_entry("shared_default", log_read=False)
        assert uploaded_default is not None
        assert uploaded_default.policy == "session"

        tok_prompt = encode_share_token(
            Entry(name="shared_strict", fields={"TOKEN": "tok_strict_123"}, policy="prompt"),
            passphrase=None,
        )
        with patch("passkey.interactive.prompt_secret", return_value=tok_prompt):
            cmd_upload()
        uploaded_strict = _get_entry("shared_strict", log_read=False)
        assert uploaded_strict is not None
        assert uploaded_strict.policy == "prompt"
        capsys.readouterr()

    def test_bulk_policy_all_and_exclude_mcp_preserves_metadata(self, tmp_path, capsys):
        from passkey.keychain import get_entry_meta
        from passkey.mcp_config import ADAPTERS, ToolAdapter

        # Create CLI/agent entries + MCP entries (import-mcp, cursor-init, and actively wrapped)
        save_entry(
            Entry(
                name="jamf",
                fields={"JAMF_SECRET": "j_123"},
                config={"JAMF_URL": "https://corp.jamfcloud.com"},
                created="2026-01-10T00:00:00",
                last_rotated="2026-02-10T00:00:00",
                source="manual",
                policy="allow",
            )
        )
        save_entry(Entry(name="aws", fields={"AWS_KEY": "a_123"}, source="manual", policy="allow"))
        save_entry(
            Entry(name="gh_mcp", fields={"GH_TOKEN": "g_123"}, source="import-mcp", policy="allow")
        )
        save_entry(
            Entry(
                name="linear_mcp",
                fields={"LINEAR_KEY": "l_123"},
                source="cursor-init",
                policy="allow",
            )
        )
        save_entry(
            Entry(
                name="wrapped_manual",
                fields={"SLACK_TOKEN": "s_123"},
                source="manual",
                policy="allow",
            )
        )

        mcp_cfg = tmp_path / "claude.json"
        mcp_cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "slack": {
                            "command": "passkey",
                            "args": ["run", "--quiet", "wrapped_manual", "--", "slack-mcp"],
                        }
                    }
                }
            )
        )
        fake_adapter = ToolAdapter(
            name="claude",
            display_name="Claude Code",
            root_key="mcpServers",
            global_paths={sys.platform: mcp_cfg},
        )

        with (
            patch.dict(ADAPTERS, {"claude": fake_adapter}, clear=True),
            patch.object(
                sys,
                "argv",
                ["passkey", "policy", "--all", "session", "--exclude-mcp", "--yes", "--json"],
            ),
        ):
            main()

        res = json.loads(capsys.readouterr().out)
        assert res == {
            "ok": True,
            "policy": "session",
            "updated_count": 2,
            "unchanged_count": 0,
            "excluded_mcp_count": 3,
            "updated": ["aws", "jamf"],
            "unchanged": [],
            "excluded_mcp": ["gh_mcp", "linear_mcp", "wrapped_manual"],
        }

        # Verify both Keychain Entry (with whole-Entry metadata preserved!) and entries.json v2 index
        jamf_after = _get_entry("jamf", log_read=False)
        assert jamf_after is not None
        assert jamf_after.policy == "session"
        assert jamf_after.config == {"JAMF_URL": "https://corp.jamfcloud.com"}
        assert jamf_after.created == "2026-01-10T00:00:00"
        assert jamf_after.last_rotated == "2026-02-10T00:00:00"
        assert get_entry_meta("jamf").policy == "session"
        assert get_entry_meta("aws").policy == "session"

        # MCP entries remained headless 'allow'
        for mcp_name in ("gh_mcp", "linear_mcp", "wrapped_manual"):
            assert _get_entry(mcp_name, log_read=False).policy == "allow"
            assert get_entry_meta(mcp_name).policy == "allow"

        # Switch ALL entries to YOLO 'allow' in one pass
        with (
            patch.dict(ADAPTERS, {"claude": fake_adapter}, clear=True),
            patch.object(sys, "argv", ["passkey", "policy", "--all", "allow", "-y", "--json"]),
        ):
            main()

        res_yolo = json.loads(capsys.readouterr().out)
        assert res_yolo["updated"] == ["aws", "jamf"]
        assert res_yolo["unchanged"] == ["gh_mcp", "linear_mcp", "wrapped_manual"]
        assert get_entry_meta("jamf").policy == "allow"

        # Non-interactive without --yes fails fast with exit code 2
        with (
            patch.object(sys, "argv", ["passkey", "--no-input", "policy", "--all", "session"]),
            pytest.raises(SystemExit) as exc_ni,
        ):
            main()
        assert exc_ni.value.code == 2
        capsys.readouterr()

        # Invalid flag combinations fail cleanly with exit code 1
        for bad_argv in (
            ["passkey", "policy", "jamf", "session", "--exclude-mcp"],
            ["passkey", "policy", "--all", "jamf", "session", "--yes"],
            ["passkey", "policy", "--all"],
        ):
            with patch.object(sys, "argv", bad_argv), pytest.raises(SystemExit) as exc_bad:
                main()
            assert exc_bad.value.code == 1
            capsys.readouterr()

    def test_bulk_policy_exclude_mcp_empty_targets_skips_prompt(self, capsys):
        from passkey.commands import cmd_policy_all

        save_entry(
            Entry(name="only_mcp", fields={"GH_TOKEN": "g_123"}, source="import-mcp", policy="allow")
        )

        # Must NOT call input() when --exclude-mcp filters out all entries (even with yes=False)
        with patch("builtins.input") as mock_input:
            cmd_policy_all("session", exclude_mcp=True, yes=False, json_output=False)
        mock_input.assert_not_called()
        human_out = capsys.readouterr().out
        assert "No matching non-MCP entries to update (1 MCP entry(s) excluded)." in human_out

        with patch("builtins.input") as mock_input_json:
            cmd_policy_all("session", exclude_mcp=True, yes=False, json_output=True)
        mock_input_json.assert_not_called()
        json_out = json.loads(capsys.readouterr().out)
        assert json_out == {
            "ok": True,
            "policy": "session",
            "updated_count": 0,
            "unchanged_count": 0,
            "excluded_mcp_count": 1,
            "updated": [],
            "unchanged": [],
            "excluded_mcp": ["only_mcp"],
        }
