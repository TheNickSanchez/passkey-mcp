"""Tests for Tier P0 Agent-Experience (AX) upgrades.

Covers:
- Non-TTY, --no-input, and PTY-backed AI agent subprocess fail-fast (exit code 2)
- Confirmation bypasses (--yes on delete/init/audit --clear; --touch-only on rotate)
- Lazy import of FastMCP server (passkey.mcp_server not loaded on CLI startup)
- Deterministic secret-free --json output on list, info, check, doctor, status, servers
- Read-only peek_lease() preserving max_uses=1 leases across inspection & dry-run
- passkey run --dry-run [--json], --strict, and automatic agent banner suppression
"""

import io
import json
import subprocess
import sys
from unittest.mock import patch

import pytest

from passkey.audit import get_recent_logs
from passkey.cli import main
from passkey.health import cmd_rotate
from passkey.interactive import (
    can_prompt_interactively,
    is_agent_subprocess,
    is_interactive,
)
from passkey.keychain import PasskeyError, get_entry, save_entry
from passkey.leases import grant_lease, peek_lease
from passkey.mcp_config import ADAPTERS, ToolAdapter
from passkey.models import Entry


class TestNonTtyAndAgentFailFast:
    """Verify interactive commands fail fast with exit code 2 and actionable guidance."""

    @pytest.mark.parametrize(
        "argv",
        [
            ["passkey"],
            ["passkey", "new", "stripe"],
            ["passkey", "entry", "new", "stripe"],
            ["passkey", "edit", "stripe"],
            ["passkey", "get", "stripe"],
            ["passkey", "get", "stripe", "--all"],
            ["passkey", "delete", "stripe"],
            ["passkey", "set-field", "stripe", "API_KEY"],
            ["passkey", "rotate", "stripe"],
            ["passkey", "init"],
            ["passkey", "add", "stripe"],
            ["passkey", "share"],
            ["passkey", "share", "stripe"],
            ["passkey", "upload"],
            ["passkey", "receive", "bundle.enc"],
            ["passkey", "export", "backup.enc", "--encrypt"],
            ["passkey", "import", "backup.enc", "--decrypt"],
            ["passkey", "audit", "--clear"],
            ["passkey", "template", "apply", "github"],
            ["passkey", "template", "add"],
            ["passkey", "stripe"],
        ],
    )
    def test_interactive_commands_exit_2_on_non_tty(self, argv, capsys):
        save_entry(Entry(name="stripe", fields={"STRIPE_SECRET_KEY": "sk_live_top_secret_999"}))

        with (
            patch("passkey.interactive.is_interactive", return_value=False),
            patch.object(sys, "argv", argv),
            pytest.raises(SystemExit) as exc,
        ):
            main()

        assert exc.value.code == 2
        captured = capsys.readouterr()
        assert "sk_live_top_secret_999" not in captured.out
        assert "sk_live_top_secret_999" not in captured.err
        assert "Never ask the user to paste secret values into chat" in captured.err

    @pytest.mark.parametrize(
        "argv",
        [
            ["passkey", "--no-input", "new", "stripe"],
            ["passkey", "new", "stripe", "--no-input"],
            ["passkey", "entry", "new", "stripe", "--no-input"],
            ["passkey", "--no-input", "stripe"],
            ["passkey", "stripe", "--no-input"],
            ["passkey", "get", "stripe", "--no-input"],
        ],
    )
    def test_no_input_flag_blocks_even_when_tty_is_true(self, argv, monkeypatch, capsys):
        save_entry(Entry(name="stripe", fields={"API_KEY": "sk_live_never_leak"}))
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

        with patch.object(sys, "argv", argv), pytest.raises(SystemExit) as exc:
            main()

        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "--no-input is set" in err
        assert "sk_live_never_leak" not in err

    def test_pty_agent_env_vars_block_prompts_while_vscode_pid_allows_humans(self, monkeypatch):
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)

        # Human developer in VS Code / Cursor integrated terminal must remain interactive
        monkeypatch.setenv("VSCODE_PID", "42424")
        monkeypatch.setenv("CURSOR_TRACE_ID", "trace-abc")
        assert is_agent_subprocess() is False
        assert is_interactive() is True
        assert can_prompt_interactively() is True

        # Headless agent inside PTY shell must be detected as non-interactive
        monkeypatch.setenv("CLAUDECODE", "1")
        assert is_agent_subprocess() is True
        assert is_interactive() is False
        assert can_prompt_interactively() is False

        # Explicit override restores interactive mode
        monkeypatch.setenv("PASSKEY_ALLOW_INTERACTIVE", "1")
        assert is_agent_subprocess() is False
        assert can_prompt_interactively() is True

    def test_positional_command_typo_gives_did_you_mean_hint(self, capsys):
        with patch.object(sys, "argv", ["passkey", "stauts"]), pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "Did you mean 'passkey status'?" in err

    def test_multi_token_unknown_command_does_not_open_entry_browser(self, capsys):
        save_entry(Entry(name="myentry", fields={"K": "V"}))
        with (
            patch.object(sys, "argv", ["passkey", "myentry", "unexpected"]),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        # argparse rejects invalid command choice with code 2
        assert exc.value.code == 2
        assert "invalid choice" in capsys.readouterr().err

    def test_yes_and_touch_only_flags_succeed_headlessly(self, tmp_path, capsys):
        save_entry(
            Entry(
                name="rot_me",
                fields={"SECRET": "keep_existing_val"},
                config={"REGION": "us-east-1"},
            )
        )

        # 1. rotate --touch-only
        with patch.object(sys, "argv", ["passkey", "rotate", "rot_me", "--touch-only"]):
            main()
        rotated = get_entry("rot_me")
        assert rotated is not None
        assert rotated.last_rotated is not None
        assert rotated.fields["SECRET"] == "keep_existing_val"
        assert rotated.config == {"REGION": "us-east-1"}

        # 2. delete --yes
        with patch.object(sys, "argv", ["passkey", "delete", "rot_me", "--yes"]):
            main()
        assert get_entry("rot_me") is None

        # 3. audit --clear --yes
        with patch.object(sys, "argv", ["passkey", "audit", "--clear", "--yes"]):
            main()
        assert get_recent_logs() == []

        # 4. init --yes
        cfg = tmp_path / "claude.json"
        cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "gh_srv": {
                            "command": "npx",
                            "args": ["-y", "srv"],
                            "env": {"GITHUB_TOKEN": "ghp_headless_migrate_123456"},
                        }
                    }
                }
            )
        )
        fake_claude = ToolAdapter(
            name="claude",
            display_name="Claude Code",
            root_key="mcpServers",
            global_paths={sys.platform: cfg},
        )
        with (
            patch.dict(ADAPTERS, {"claude": fake_claude}, clear=True),
            patch.object(
                sys,
                "argv",
                ["passkey", "init", "--tool", "claude", "--config", str(cfg), "--yes"],
            ),
        ):
            main()
        migrated = get_entry("gh_srv")
        assert migrated is not None
        assert migrated.fields == {"GITHUB_TOKEN": "ghp_headless_migrate_123456"}
        capsys.readouterr()

    def test_rotate_aborts_on_eof_without_stamping_last_rotated(self, monkeypatch):
        save_entry(Entry(name="eof_test", fields={"API_KEY": "original_secret"}))
        monkeypatch.setattr(sys, "stdin", io.StringIO(""))

        with pytest.raises(PasskeyError, match="rotation aborted"):
            cmd_rotate("eof_test", "API_KEY")

        unchanged = get_entry("eof_test")
        assert unchanged is not None
        assert unchanged.fields["API_KEY"] == "original_secret"
        assert unchanged.last_rotated is None

    def test_cli_does_not_eagerly_import_mcp_server(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys, passkey.cli; "
                    "assert 'passkey.mcp_server' not in sys.modules, "
                    "'mcp_server was eagerly imported!'"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr


class TestDeterministicJsonOutput:
    """Verify --json across list, info, check, doctor, status, and servers never leaks values."""

    def test_list_and_info_json_contracts_and_lease_preservation(self, capsys):
        secret_val = "sk_live_NEVER_APPEAR_IN_JSON_999"
        config_val = "https://internal-secret-endpoint.corp.local"

        # Empty list --json -> []
        with patch.object(sys, "argv", ["passkey", "list", "--json"]):
            main()
        assert json.loads(capsys.readouterr().out) == []

        save_entry(
            Entry(
                name="stripe_prod",
                fields={"STRIPE_SECRET_KEY": secret_val},
                config={"ENDPOINT_URL": config_val},
                policy="prompt",
                source="manual",
            )
        )
        grant_lease("stripe_prod", ttl="15m", max_uses=1, require_biometric=False)

        # list --json
        with patch.object(sys, "argv", ["passkey", "list", "--json"]):
            main()
        raw_list = capsys.readouterr().out
        assert secret_val not in raw_list
        assert config_val not in raw_list
        parsed_list = json.loads(raw_list)
        assert len(parsed_list) == 1
        item = parsed_list[0]
        assert item["name"] == "stripe_prod"
        assert item["fields"] == ["STRIPE_SECRET_KEY"]
        assert item["config_keys"] == ["ENDPOINT_URL"]
        assert item["policy"] == "prompt"
        assert item["has_active_lease"] is True

        # info --json
        with patch.object(sys, "argv", ["passkey", "info", "stripe_prod", "--json"]):
            main()
        raw_info = capsys.readouterr().out
        assert secret_val not in raw_info
        assert config_val not in raw_info
        parsed_info = json.loads(raw_info)
        assert parsed_info["name"] == "stripe_prod"
        assert parsed_info["policy"] == "prompt"
        assert parsed_info["has_active_lease"] is True
        assert parsed_info["lease_remaining_uses"] == 1
        assert parsed_info["will_prompt_biometric"] is False
        assert parsed_info["fields"] == ["STRIPE_SECRET_KEY"]
        assert parsed_info["config_keys"] == ["ENDPOINT_URL"]

        # Lease with max_uses=1 MUST still have 1 remaining use!
        still_active = peek_lease("stripe_prod")
        assert still_active is not None
        assert still_active["remaining_uses"] == 1

    def test_check_json_valid_and_missing(self, capsys):
        save_entry(Entry(name="svc", fields={"API_KEY": "top_secret_val"}, config={"ENV": "prod"}))

        with (
            patch.object(sys, "argv", ["passkey", "check", "svc", "API_KEY", "ENV", "--json"]),
            pytest.raises(SystemExit) as exc_ok,
        ):
            main()
        assert exc_ok.value.code == 0
        ok_data = json.loads(capsys.readouterr().out)
        assert ok_data["valid"] is True
        assert ok_data["present"] == ["API_KEY", "ENV"]
        assert ok_data["missing"] == []
        assert "top_secret_val" not in json.dumps(ok_data)

        with (
            patch.object(sys, "argv", ["passkey", "check", "svc", "API_KEY", "MISSING_KEY", "--json"]),
            pytest.raises(SystemExit) as exc_miss,
        ):
            main()
        assert exc_miss.value.code == 1
        miss_data = json.loads(capsys.readouterr().out)
        assert miss_data["valid"] is False
        assert miss_data["missing"] == ["MISSING_KEY"]
        assert "passkey entry set-field svc MISSING_KEY" in miss_data["remediation"]

    def test_status_servers_and_doctor_json(self, capsys):
        with patch.dict(ADAPTERS, {}, clear=True):
            with patch.object(sys, "argv", ["passkey", "status", "--json"]):
                main()
            assert json.loads(capsys.readouterr().out) == []

            with patch.object(sys, "argv", ["passkey", "servers", "--json"]):
                main()
            assert json.loads(capsys.readouterr().out) == []

            with (
                patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
                patch.object(sys, "argv", ["passkey", "doctor", "--json"]),
            ):
                main()
            doc_ok = json.loads(capsys.readouterr().out)
            assert doc_ok["summary"]["failed"] == 0

            with (
                patch("passkey.doctor.find_passkey_command", return_value=None),
                patch.object(sys, "argv", ["passkey", "doctor", "--json"]),
                pytest.raises(SystemExit) as exc_fail,
            ):
                main()
            assert exc_fail.value.code == 1
            doc_fail = json.loads(capsys.readouterr().out)
            assert doc_fail["summary"]["failed"] >= 1


class TestRunDryRunStrictAndAgentBanner:
    """Verify passkey run --dry-run [--json], --strict, and banner suppression."""

    def test_run_dry_run_json_validates_without_spawning_or_leaking(self, tmp_path, capsys):
        secret_a = "sk_live_dryrun_secret_value_abc"
        secret_b = "whsec_dryrun_webhook_secret_xyz"
        save_entry(
            Entry(
                name="stripe",
                fields={"STRIPE_KEY": secret_a},
                config={"STRIPE_API_VERSION": "2025-01-01"},
                policy="prompt",
            )
        )
        save_entry(Entry(name="webhooks", fields={"WEBHOOK_SECRET": secret_b}, policy="allow"))
        grant_lease("stripe", ttl="10m", max_uses=1, require_biometric=False)

        env_file = tmp_path / ".env.passkey"
        env_file.write_text("MAPPED_WH=passkey://webhooks/WEBHOOK_SECRET\nSTATIC_PORT=8080\n")
        marker_file = tmp_path / "should_never_exist.txt"

        # Test flags placed after entry name + child command that MUST NOT run
        argv = [
            "passkey",
            "run",
            "stripe",
            "--env-file",
            str(env_file),
            "--dry-run",
            "--json",
            "--",
            sys.executable,
            "-c",
            f"open({str(marker_file)!r}, 'w').write('ran')",
        ]
        with patch.object(sys, "argv", argv), pytest.raises(SystemExit) as exc:
            main()

        assert exc.value.code == 0
        assert not marker_file.exists()

        captured = capsys.readouterr()
        assert secret_a not in captured.out
        assert secret_b not in captured.out
        assert "2025-01-01" not in captured.out
        assert "8080" not in captured.out

        report = json.loads(captured.out)
        assert report["ready"] is True
        assert report["will_prompt_biometric"] is False
        assert report["command_executable_found"] is True
        assert set(report["injected_env_vars"]) == {
            "STRIPE_KEY",
            "STRIPE_API_VERSION",
            "MAPPED_WH",
            "STATIC_PORT",
        }

        # Lease with max_uses=1 must remain untouched after --dry-run
        lease = peek_lease("stripe")
        assert lease is not None
        assert lease["remaining_uses"] == 1

    def test_run_dry_run_without_command_and_missing_entry_reports_remediation(self, capsys):
        save_entry(Entry(name="vault_prod", fields={"TOKEN": "s3cr3t"}, policy="prompt"))

        with (
            patch.object(sys, "argv", ["passkey", "run", "vault_prod", "missing_db", "--dry-run", "--json"]),
            pytest.raises(SystemExit) as exc,
        ):
            main()

        assert exc.value.code == 1
        report = json.loads(capsys.readouterr().out)
        assert report["ready"] is False
        assert report["entries_missing"] == ["missing_db"]
        assert report["will_prompt_biometric"] is True
        assert report["prompt_entries_without_lease"] == ["vault_prod"]
        assert any("passkey new missing_db" in r for r in report["remediation"])
        assert any("passkey lease grant vault_prod" in r for r in report["remediation"])

    def test_run_strict_aborts_when_one_of_multiple_entries_is_missing(self, capsys):
        save_entry(Entry(name="present_svc", fields={"KEY": "val123"}))

        with (
            patch.object(
                sys,
                "argv",
                [
                    "passkey",
                    "run",
                    "--strict",
                    "present_svc",
                    "missing_svc",
                    "--",
                    sys.executable,
                    "-c",
                    "print('should_not_run')",
                ],
            ),
            pytest.raises(SystemExit) as exc,
        ):
            main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "should_not_run" not in captured.out
        assert "passkey new missing_svc" in captured.err

    def test_agent_subprocess_auto_suppresses_security_warning_banner(self, monkeypatch, capsys):
        save_entry(Entry(name="svc", fields={"API_KEY": "supersecretvalue"}))
        monkeypatch.setenv("CLAUDECODE", "1")

        with (
            patch.object(
                sys,
                "argv",
                ["passkey", "run", "svc", "--", sys.executable, "-c", "print('hello_agent')"],
            ),
            pytest.raises(SystemExit) as exc,
        ):
            main()

        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "hello_agent" in captured.out
        assert "SECURITY WARNING" not in captured.err
