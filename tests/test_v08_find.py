"""Tests for v0.8.0 Milestone 2: Reverse Env-Var Lookup (passkey find & passkey_find)."""

import json
import sys
from unittest.mock import patch

import pytest

from passkey.audit import get_recent_logs
from passkey.cli import main
from passkey.keychain import save_entry
from passkey.mcp_server import passkey_find
from passkey.models import Entry


class TestPasskeyFind:
    """Verify exact, specific-alias, and entry-scoped lookup without leaking values."""

    def test_exact_alias_entry_stem_and_no_cross_service_false_positives(self, capsys):
        secret_resend = "re_SUPER_SECRET_RESEND_999"
        secret_gh = "ghp_SUPER_SECRET_GH_888"
        secret_slack = "xoxb_SLACK_GENERIC_TOKEN_777"
        cfg_region = "us-west-2"

        save_entry(Entry(name="email_svc", fields={"RESEND_API_KEY": secret_resend}))
        save_entry(Entry(name="gh_work", fields={"GITHUB_TOKEN": secret_gh}))
        save_entry(Entry(name="posthog", fields={"API_KEY": "phc_secret_666"}))
        save_entry(Entry(name="slack", fields={"TOKEN": secret_slack}))
        save_entry(Entry(name="aws_dev", fields={"AWS_SECRET_ACCESS_KEY": "aws_sec"}, config={"AWS_REGION": cfg_region}))

        reads_before = [r for r in get_recent_logs() if r.get("operation") == "read"]

        with patch.object(
            sys,
            "argv",
            [
                "passkey",
                "find",
                "RESEND_API_KEY",
                "GH_TOKEN",
                "POSTHOG_API_KEY",
                "OPENAI_API_KEY",
                "AWS_DEFAULT_REGION",
                "--json",
            ],
        ):
            main()

        raw = capsys.readouterr().out
        for secret in (secret_resend, secret_gh, secret_slack, "phc_secret_666", cfg_region):
            assert secret not in raw

        data = json.loads(raw)
        assert data["ok"] is True
        assert data["all_found"] is False
        assert data["missing_vars"] == ["OPENAI_API_KEY"]

        # 1. Exact match
        assert data["matches"]["RESEND_API_KEY"][0]["entry"] == "email_svc"
        assert data["matches"]["RESEND_API_KEY"][0]["match_type"] == "exact"
        assert data["matches"]["RESEND_API_KEY"][0]["reference"] == "passkey://email_svc/RESEND_API_KEY"

        # 2. Specific synonym match (GH_TOKEN -> GITHUB_TOKEN)
        assert data["matches"]["GH_TOKEN"][0]["entry"] == "gh_work"
        assert data["matches"]["GH_TOKEN"][0]["field"] == "GITHUB_TOKEN"
        assert data["matches"]["GH_TOKEN"][0]["match_type"] == "alias"

        # 3. Entry-scoped generic field stem (POSTHOG_API_KEY -> posthog/API_KEY)
        assert data["matches"]["POSTHOG_API_KEY"][0]["entry"] == "posthog"
        assert data["matches"]["POSTHOG_API_KEY"][0]["field"] == "API_KEY"
        assert data["matches"]["POSTHOG_API_KEY"][0]["match_type"] == "entry_alias"

        # 4. Generic 'TOKEN' inside 'slack' MUST NOT falsely match OPENAI_API_KEY!
        assert data["matches"]["OPENAI_API_KEY"] == []

        # 5. Config key synonym match (AWS_DEFAULT_REGION -> aws_dev/AWS_REGION)
        assert data["matches"]["AWS_DEFAULT_REGION"][0]["entry"] == "aws_dev"
        assert data["matches"]["AWS_DEFAULT_REGION"][0]["kind"] == "config"

        # 6. Zero 'read' audit entries logged
        reads_after = [r for r in get_recent_logs() if r.get("operation") == "read"]
        assert len(reads_after) == len(reads_before)

    def test_from_file_env_example_and_sensitive_dotenv_rejection(self, tmp_path, capsys):
        save_entry(Entry(name="stripe", fields={"STRIPE_SECRET_KEY": "sk_live_never_leak"}))

        env_example = tmp_path / ".env.example"
        env_example.write_text(
            "# Example configuration\n"
            "STRIPE_API_KEY=sk_test_placeholder\n"
            "UNCONFIGURED_VAR=\n",
            encoding="utf-8",
        )

        # MCP passkey_find with from_file
        mcp_res = passkey_find(from_file=str(env_example))
        assert mcp_res["ok"] is True
        assert mcp_res["matches"]["STRIPE_API_KEY"][0]["entry"] == "stripe"
        assert mcp_res["matches"]["STRIPE_API_KEY"][0]["field"] == "STRIPE_SECRET_KEY"
        assert mcp_res["missing_vars"] == ["UNCONFIGURED_VAR"]
        assert "sk_live_never_leak" not in json.dumps(mcp_res)

        # Refuses live .env on both CLI and MCP!
        live_env = tmp_path / ".env"
        live_env.write_text("STRIPE_SECRET_KEY=sk_live_real\n", encoding="utf-8")

        mcp_blocked = passkey_find(from_file=str(live_env))
        assert mcp_blocked["ok"] is False
        assert mcp_blocked["error_code"] == "SENSITIVE_FILE_REFUSED"

        with (
            patch.object(sys, "argv", ["passkey", "find", "--from-file", str(live_env), "--json"]),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        assert exc.value.code == 1
        cli_blocked = json.loads(capsys.readouterr().out)
        assert cli_blocked["error_code"] == "SENSITIVE_FILE_REFUSED"

        #Forbidden system path rejected on MCP
        sys_blocked = passkey_find(from_file="/etc/passwd")
        assert sys_blocked["ok"] is False
        assert sys_blocked["error_code"] == "FORBIDDEN_PATH"
