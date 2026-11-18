"""Tests for Wave 1 stream secret masking, value scanning, backups, and MCP locks."""

import io
import json
import sys
from unittest.mock import patch

import pytest

from passkey.cli.parser import create_parser
from passkey.commands import cmd_export
from passkey.doctor import run_diagnostics
from passkey.keychain import PasskeyError, save_entry
from passkey.masking import CONCEALED_TEXT, SecretMasker
from passkey.mcp_config import (
    ADAPTERS,
    ToolAdapter,
    backup_config,
    extract_secrets,
    get_original_command,
    get_server_security_status,
    rewrite_server_for_passkey,
)
from passkey.mcp_server import _validate_config_paths, passkey_wrap_server
from passkey.models import Entry
from passkey.runner import run_with_secrets
from passkey.settings import set_setting


class TestSecretMaskerUnit:
    """Unit tests for SecretMasker byte scrubbing and chunk boundary holdback."""

    def test_masks_raw_secret_and_ignores_short_values(self):
        masker = SecretMasker(["abc", "super_secret_token"])
        out = masker.feed(b"short=abc token=super_secret_token\n") + masker.flush()
        text = out.decode("utf-8")
        assert "abc" in text
        assert "super_secret_token" not in text
        assert f"token={CONCEALED_TEXT}" in text

    def test_masks_json_escaped_secret(self):
        secret = 'line1\n"quoted"\tvalue'
        masker = SecretMasker([secret])
        payload = json.dumps({"error": f"Auth failed for {secret}"}).encode("utf-8") + b"\n"
        out = masker.feed(payload) + masker.flush()
        decoded = json.loads(out.decode("utf-8"))
        assert secret not in decoded["error"]
        assert CONCEALED_TEXT in decoded["error"]

    def test_catches_secret_split_across_single_byte_chunks(self):
        secret = "ghp_1234567890abcdefghij"
        masker = SecretMasker([secret])
        raw_stream = f"header:{secret}:footer\n".encode()
        emitted = bytearray()
        for byte in raw_stream:
            emitted.extend(masker.feed(bytes([byte])))
        emitted.extend(masker.flush())
        result = emitted.decode("utf-8")
        assert secret not in result
        assert result == f"header:{CONCEALED_TEXT}:footer\n"

    def test_longer_secret_takes_precedence_over_prefix_secret(self):
        masker = SecretMasker(["secret123", "secret123456789"])
        out = masker.feed(b"val=secret123456789!\n") + masker.flush()
        assert out.decode("utf-8") == f"val={CONCEALED_TEXT}!\n"

    def test_newline_jsonrpc_frame_flushes_immediately_without_waiting_for_eof(self):
        masker = SecretMasker(["sk-abcdefghijklmnopqrstuv"])
        frame = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}\n'
        emitted = masker.feed(frame)
        assert emitted == frame


class TestRunnerStreamMasking:
    """End-to-end subprocess masking tests for passkey run."""

    def test_masks_stdout_and_stderr_while_preserving_config_values(self, capsys):
        save_entry(
            Entry(
                name="svc",
                fields={"API_SECRET": "sk-live-9876543210abcdef"},
                config={"PUBLIC_URL": "https://api.example.com"},
            )
        )
        script = (
            "import os, json, sys; "
            "sys.stdout.write('out=' + os.environ['API_SECRET'] + ' url=' + os.environ['PUBLIC_URL'] + '\\n'); "
            "sys.stdout.flush(); "
            "sys.stderr.write(json.dumps({'err': os.environ['API_SECRET']}) + '\\n'); "
            "sys.stderr.flush()"
        )
        rc = run_with_secrets(["svc"], [sys.executable, "-c", script], quiet=True)
        assert rc == 0
        captured = capsys.readouterr()
        assert "sk-live-9876543210abcdef" not in captured.out
        assert "sk-live-9876543210abcdef" not in captured.err
        assert CONCEALED_TEXT in captured.out
        assert CONCEALED_TEXT in captured.err
        assert "https://api.example.com" in captured.out
        assert "SECURITY WARNING" not in captured.err

    def test_blocks_slow_drip_split_chunk_exfiltration(self, capsys):
        secret = "sk-drip-attack-secret-value-999"
        save_entry(Entry(name="drip", fields={"API_SECRET": secret}))
        script = (
            "import os, time; "
            "s = os.environ['API_SECRET'].encode(); "
            "os.write(1, s[:4]); "
            "time.sleep(0.05); "
            "os.write(1, s[4:] + b'\\n')"
        )
        rc = run_with_secrets(["drip"], [sys.executable, "-c", script], quiet=True)
        assert rc == 0
        out = capsys.readouterr().out
        assert secret not in out
        assert "sk-d" not in out
        assert out.strip() == CONCEALED_TEXT

    def test_no_masking_flag_allows_raw_output(self, capsys):
        save_entry(Entry(name="svc", fields={"API_SECRET": "sk-live-raw-allowed-12345"}))
        # Using python to write to a file or checking returncode with subprocess
        rc = run_with_secrets(
            ["svc"],
            [sys.executable, "-c", "import os; assert os.environ['API_SECRET'] == 'sk-live-raw-allowed-12345'"],
            no_masking=True,
            quiet=True,
        )
        assert rc == 0
        assert capsys.readouterr().err == ""


class TestWave1HardeningAndMCPFixes:
    """Tests for Wave 1 CLI hardening, OpenCode status, backups, value scanner, and D3-4 lock."""

    def test_export_stdout_blocks_non_tty_stdin(self, monkeypatch):
        save_entry(Entry(name="prod", fields={"TOKEN": "secret-token-value"}))
        fake_stdin = io.StringIO("y\n")
        monkeypatch.setattr(sys, "stdin", fake_stdin)
        with pytest.raises(PasskeyError, match="interactive terminal"):
            cmd_export("-", no_secrets=False)

    def test_set_field_parser_rejects_positional_secret_value(self):
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["set-field", "myentry", "API_KEY", "leaked_secret_in_argv"])

    def test_opencode_array_command_reports_secured_and_roundtrips(self):
        adapter = ADAPTERS["opencode"]
        original = {
            "command": ["npx", "-y", "@modelcontextprotocol/server-github"],
            "environment": {"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwx"},
        }
        wrapped = rewrite_server_for_passkey("github", original, adapter)
        assert wrapped["command"][:4] == ["passkey", "run", "--quiet", "github"]
        cmd, cmd_args = get_original_command(wrapped)
        assert cmd == "npx"
        assert cmd_args == ["-y", "@modelcontextprotocol/server-github"]

        status = get_server_security_status("github", wrapped, ["github"], adapter)
        assert status["status"] == "secured"
        assert status["passkey_entry"] == "github"

    def test_backup_relocated_to_data_dir_and_doctor_warns_on_lingering_backup(
        self, tmp_path, isolated_data_dir
    ):
        cfg = tmp_path / "mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        bkp = backup_config(cfg)
        assert bkp.parent == isolated_data_dir / "backups"
        assert oct(bkp.stat().st_mode & 0o777) == "0o600"
        assert not (tmp_path / "mcp.json.backup").exists()

        # Create a lingering adjacent .backup and verify doctor flags it
        lingering = tmp_path / "mcp.json.backup"
        lingering.write_text('{"mcpServers": {"s": {"env": {"TOKEN": "x"}}}}')
        adapter = ToolAdapter(
            name="cursor",
            display_name="Cursor",
            root_key="mcpServers",
            global_paths={sys.platform: cfg},
        )
        with (
            patch("passkey.doctor.ADAPTERS", {"cursor": adapter}),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
        ):
            diag = run_diagnostics()
        assert any(c["name"] == "cursor_backup" and c["status"] == "warn" for c in diag["checks"])

    def test_extract_secrets_detects_value_patterns_under_generic_names(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
        env = {
            "DATABASE_URL": "postgresql://admin:s3cr3tP@ss@db.example.com:5432/app",
            "GH_UPSTREAM": "ghp_1234567890abcdefghijklmn",
            "GH_FINE": "github_pat_1234567890abcdefghijklmnop",
            "LLM_ENDPOINT": "sk-proj-1234567890abcdefghijklmnop",
            "SLACK_HOOK": "xoxb-123456789-abcdefghi",
            "CLOUD_ID": "AKIAIOSFODNN7EXAMPLE",
            "SESSION_BLOB": jwt,
            "SAFE_URL": "https://api.example.com/v1",
            "REF_VAR": "passkey://prod/DB_URL",
        }
        secrets, non_secrets = extract_secrets(env)
        assert set(secrets.keys()) == {
            "DATABASE_URL",
            "GH_UPSTREAM",
            "GH_FINE",
            "LLM_ENDPOINT",
            "SLACK_HOOK",
            "CLOUD_ID",
            "SESSION_BLOB",
        }
        assert set(non_secrets.keys()) == {"SAFE_URL", "REF_VAR"}

    def test_mcp_write_tools_lock_and_forbidden_macos_paths(self, tmp_path):
        save_entry(Entry(name="srv", fields={"TOKEN": "secret1234"}))
        set_setting("mcp_write_tools", False)
        res = passkey_wrap_server("srv")
        assert res["success"] is False
        assert "disabled" in res["message"].lower()

        valid_cfg = tmp_path / "mcp.json"
        valid_cfg.write_text("{}")
        validated = _validate_config_paths(
            ["/etc/mcp.json", "/private/etc/mcp.json", "/private/var/root/mcp.json", str(valid_cfg)]
        )
        assert validated == [valid_cfg.resolve()]
