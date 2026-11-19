"""Tests for v0.8.0 Milestone 5: Out-of-band native secret capture (passkey request)."""

import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from passkey.audit import get_log_path
from passkey.cli import main
from passkey.keychain import PasskeyError, _get_entry, save_entry
from passkey.mcp_server import passkey_request_secret
from passkey.models import Entry
from passkey.request_secret import _APPLESCRIPT_HIDDEN_DIALOG, request_secret
from passkey.settings import set_setting


class TestOutOfBandSecretRequest:
    """Verify native OS secret capture, AppleScript injection immunity, and rate-limiting."""

    def test_cli_request_creates_and_merges_entry_without_leaking_secrets(
        self, monkeypatch, capsys
    ):
        monkeypatch.setattr("passkey.request_secret.sys.platform", "darwin")
        monkeypatch.setenv("CLAUDECODE", "1")

        secret_a = "sk_test_oob_captured_alpha_999"
        secret_b = "whsec_oob_captured_beta_888"

        mock_proc_a = MagicMock(returncode=0, stdout=secret_a + "\n", stderr="")
        mock_proc_b = MagicMock(returncode=0, stdout=secret_b + "\n", stderr="")

        with (
            patch(
                "passkey.request_secret.subprocess.run",
                side_effect=[mock_proc_a, mock_proc_b],
            ) as mock_run,
            patch("passkey.request_secret.DEFAULT_COOLDOWN_SECONDS", 0.0),
            patch.object(
                sys,
                "argv",
                [
                    "passkey",
                    "request",
                    "stripe_dev",
                    "--fields",
                    "STRIPE_SECRET_KEY,WEBHOOK_SECRET",
                    "--policy",
                    "session",
                    "--hint",
                    "Stripe Dashboard -> Developers -> API keys",
                    "--json",
                ],
            ),
        ):
            main()

        assert mock_run.call_count == 2
        captured = capsys.readouterr()
        assert secret_a not in captured.out
        assert secret_b not in captured.out
        assert secret_a not in captured.err
        assert secret_b not in captured.err

        res = json.loads(captured.out)
        assert res == {
            "ok": True,
            "status": "created",
            "entry": "stripe_dev",
            "fields_saved": ["STRIPE_SECRET_KEY", "WEBHOOK_SECRET"],
            "fields_present": ["STRIPE_SECRET_KEY", "WEBHOOK_SECRET"],
            "policy": "session",
        }

        stored = _get_entry("stripe_dev", log_read=False)
        assert stored is not None
        assert stored.fields == {
            "STRIPE_SECRET_KEY": secret_a,
            "WEBHOOK_SECRET": secret_b,
        }
        assert stored.policy == "session"

        # Audit log must never contain secret values
        audit_raw = get_log_path().read_text(encoding="utf-8")
        assert secret_a not in audit_raw
        assert secret_b not in audit_raw

        # Calling again for already-present fields returns status='already_exists' with 0 popups!
        with patch("passkey.request_secret.subprocess.run") as mock_zero:
            idempotent = request_secret(
                "stripe_dev",
                ["STRIPE_SECRET_KEY", "WEBHOOK_SECRET"],
                cooldown_seconds=0.0,
            )
        mock_zero.assert_not_called()
        assert idempotent["status"] == "already_exists"
        assert idempotent["fields_saved"] == []

    def test_merge_preserves_existing_entry_metadata_and_config(self, monkeypatch):
        monkeypatch.setattr("passkey.request_secret.sys.platform", "darwin")
        save_entry(
            Entry(
                name="aws_app",
                fields={"AWS_ACCESS_KEY_ID": "AKIA_EXISTING_123"},
                config={"AWS_REGION": "us-west-2"},
                created="2026-01-15T10:00:00",
                source="import-mcp",
                last_rotated="2026-06-01T12:00:00",
                policy="prompt",
            )
        )

        new_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        mock_proc = MagicMock(returncode=0, stdout=new_secret + "\r\n", stderr="")

        with patch("passkey.request_secret.subprocess.run", return_value=mock_proc) as mock_run:
            # Requests both existing AWS_ACCESS_KEY_ID and missing AWS_SECRET_ACCESS_KEY
            res = request_secret(
                "aws_app",
                ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                cooldown_seconds=0.0,
            )

        # Only prompted ONCE (for the missing field!)
        mock_run.assert_called_once()
        assert res["status"] == "updated"
        assert res["fields_saved"] == ["AWS_SECRET_ACCESS_KEY"]

        merged = _get_entry("aws_app", log_read=False)
        assert merged is not None
        assert merged.fields == {
            "AWS_ACCESS_KEY_ID": "AKIA_EXISTING_123",
            "AWS_SECRET_ACCESS_KEY": new_secret,
        }
        assert merged.config == {"AWS_REGION": "us-west-2"}
        assert merged.created == "2026-01-15T10:00:00"
        assert merged.source == "import-mcp"
        assert merged.last_rotated == "2026-06-01T12:00:00"
        assert merged.policy == "prompt"

    def test_redteam_applescript_injection_and_no_system_events_tcc(self, monkeypatch):
        monkeypatch.setattr("passkey.request_secret.sys.platform", "darwin")
        hostile_hint = 'Stripe — Developers → Keys " & do shell script "touch /tmp/pwned" & "\x00\nNext'
        mock_proc = MagicMock(returncode=0, stdout="sec_val_safe_123\n", stderr="")

        with patch("passkey.request_secret.subprocess.run", return_value=mock_proc) as mock_run:
            request_secret(
                "safe_target",
                ["API_TOKEN"],
                hint=hostile_hint,
                cooldown_seconds=0.0,
            )

        mock_run.assert_called_once()
        call_args, call_kwargs = mock_run.call_args
        # Must use `osascript -` (stdin), NEVER `-e` argv interpolation!
        assert call_args[0] == ["osascript", "-"]
        script_stdin = call_kwargs["input"]
        assert script_stdin == _APPLESCRIPT_HIDDEN_DIALOG
        assert "System Events" not in script_stdin
        assert "do shell script" not in script_stdin
        assert "pwned" not in script_stdin

        # Title & prompt attributes must be pure 7-bit ASCII (preventing MacRoman `,Äî` mojibake)
        passed_env = call_kwargs["env"]
        assert passed_env["PASSKEY_REQ_TITLE"] == "Passkey - Secret Request"
        assert passed_env["PASSKEY_REQ_TITLE"].isascii()
        assert passed_env["PASSKEY_REQ_PROMPT"].isascii()
        assert "Stripe - Developers -> Keys" in passed_env["PASSKEY_REQ_PROMPT"]
        assert "do shell script" in passed_env["PASSKEY_REQ_PROMPT"]
        assert "\x00" not in passed_env["PASSKEY_REQ_PROMPT"]

    def test_redteam_ratelimit_cancel_timeout_and_mcp_policy(self, monkeypatch):
        monkeypatch.setattr("passkey.request_secret.sys.platform", "darwin")

        # 1. User cancel -> REQUEST_CANCELLED + rate limit blocks immediate retry
        cancel_proc = MagicMock(
            returncode=1,
            stdout="",
            stderr="execution error: User canceled. (-128)",
        )
        with (
            patch("passkey.request_secret.subprocess.run", return_value=cancel_proc),
            pytest.raises(PasskeyError) as exc_cancel,
        ):
            request_secret("cancel_me", ["SECRET_KEY"], cooldown_seconds=2.0)
        assert exc_cancel.value.error_code == "REQUEST_CANCELLED"

        # Immediate retry by runaway agent loop is blocked BEFORE spawning osascript!
        with (
            patch("passkey.request_secret.subprocess.run") as mock_blocked,
            pytest.raises(PasskeyError) as exc_rate,
        ):
            request_secret("cancel_me", ["SECRET_KEY"], cooldown_seconds=2.0)
        mock_blocked.assert_not_called()
        assert exc_rate.value.error_code == "RATE_LIMITED"

        # 2. Dialog timeout -> REQUEST_TIMEOUT
        timeout_proc = MagicMock(
            returncode=1,
            stdout="",
            stderr="execution error: PASSKEY_DIALOG_TIMEOUT (-1712)",
        )
        with (
            patch("passkey.request_secret.subprocess.run", return_value=timeout_proc),
            pytest.raises(PasskeyError) as exc_to,
        ):
            request_secret("slow_entry", ["API_KEY"], timeout=10, cooldown_seconds=0.0)
        assert exc_to.value.error_code == "REQUEST_TIMEOUT"

        # 3. Sandboxed osascript WindowServer block -> GUI_UNAVAILABLE recommending MCP tool
        sandbox_proc = MagicMock(
            returncode=1,
            stdout="",
            stderr="execution error: Operation not permitted (-10004)",
        )
        with (
            patch("passkey.request_secret.subprocess.run", return_value=sandbox_proc),
            pytest.raises(PasskeyError) as exc_gui,
        ):
            request_secret("sandboxed_entry", ["API_KEY"], cooldown_seconds=0.0)
        assert exc_gui.value.error_code == "GUI_UNAVAILABLE"
        assert "passkey_request_secret" in str(exc_gui.value)

        # 4. Subprocess hard timeout -> REQUEST_TIMEOUT
        with (
            patch(
                "passkey.request_secret.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd=["osascript", "-"], timeout=15),
            ),
            pytest.raises(PasskeyError) as exc_hard_to,
        ):
            request_secret("hung_osascript", ["API_KEY"], timeout=10, cooldown_seconds=0.0)
        assert exc_hard_to.value.error_code == "REQUEST_TIMEOUT"

        # 5. MCP passkey_request_secret respects mcp_write_tools setting
        set_setting("mcp_write_tools", False)
        mcp_denied = passkey_request_secret("mcp_entry", ["TOKEN"])
        assert mcp_denied["ok"] is False
        assert mcp_denied["error_code"] == "MCP_WRITE_DISABLED"

        set_setting("mcp_write_tools", True)
        ok_proc = MagicMock(returncode=0, stdout="mcp_secret_xyz_789\n", stderr="")
        with (
            patch("passkey.request_secret.subprocess.run", return_value=ok_proc),
            patch("passkey.request_secret.DEFAULT_COOLDOWN_SECONDS", 0.0),
        ):
            mcp_ok = passkey_request_secret("mcp_entry", ["TOKEN"], policy="session")
        assert mcp_ok["ok"] is True
        assert mcp_ok["status"] == "created"
        assert "mcp_secret_xyz_789" not in json.dumps(mcp_ok)

    def test_expired_token_rotation_sets_notification_alert_and_last_rotated(
        self, monkeypatch
    ):
        monkeypatch.setattr("passkey.request_secret.sys.platform", "darwin")
        save_entry(
            Entry(
                name="resend_rot",
                fields={"RESEND_API_KEY": "re_expired_old_0000"},
                last_rotated=None,
            )
        )

        fresh_token = "re_live_fresh_rotated_9999"
        mock_proc = MagicMock(returncode=0, stdout=fresh_token + "\n", stderr="")

        with patch("passkey.request_secret.subprocess.run", return_value=mock_proc) as mock_run:
            res = request_secret(
                "resend_rot",
                ["RESEND_API_KEY"],
                reason="HTTP 401 Unauthorized — token expired",
                hint="Resend Dashboard → API Keys → Create API Key",
                cooldown_seconds=0.0,
            )

        mock_run.assert_called_once()
        env = mock_run.call_args.kwargs["env"]
        assert env["PASSKEY_REQ_TITLE"] == "Passkey - Rotate Secret"
        assert env["PASSKEY_REQ_ACTION"] == "Update Keychain"
        assert "Alert: HTTP 401 Unauthorized - token expired" in env["PASSKEY_REQ_PROMPT"]
        assert "resend_rot/RESEND_API_KEY: HTTP 401 Unauthorized - token expired" in env[
            "PASSKEY_REQ_NOTICE"
        ]
        assert env["PASSKEY_REQ_TITLE"].isascii()
        assert env["PASSKEY_REQ_PROMPT"].isascii()
        assert env["PASSKEY_REQ_NOTICE"].isascii()

        assert res["status"] == "updated"
        assert res["rotated"] is True
        assert isinstance(res["last_rotated"], str)

        updated = _get_entry("resend_rot", log_read=False)
        assert updated is not None
        assert updated.fields["RESEND_API_KEY"] == fresh_token
        assert updated.last_rotated == res["last_rotated"]
