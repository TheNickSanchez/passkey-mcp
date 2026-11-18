"""Adversarial Red-Team security validation suite across Waves 1, 2, and 3."""

import io
import json
import os
import subprocess
import sys
from unittest.mock import patch

import pytest

from passkey.audit import get_log_path, log_operation, verify_audit_log
from passkey.browser_broker import cdp_autofill
from passkey.commands import cmd_audit, cmd_export, cmd_inject
from passkey.doctor import run_diagnostics
from passkey.keychain import PasskeyError, save_entry
from passkey.leases import (
    authorize_entry_access,
    consume_lease,
    get_leases_path,
    grant_lease,
    list_leases,
)
from passkey.mcp_server import (
    _validate_config_paths,
    passkey_cdp_autofill,
    passkey_validate_references,
    passkey_wrap_server,
)
from passkey.models import Entry
from passkey.references import parse_reference
from passkey.runner import run_with_secrets
from passkey.settings import set_setting
from tests.test_browser_broker import _MockCDPServer


class TestRedTeamStreamExfiltration:
    """Scenario 1: Chunk-split and JSON-escaped secret exfiltration on stdout and stderr."""

    def test_chunk_split_secret_exfiltration_scrubbed_on_stdout_and_stderr(self, tmp_path, capsys):
        secret = "sk-ant-redteam-split-secret-9988776655"
        save_entry(
            Entry(
                name="anthropic_prod",
                fields={"ANTHROPIC_API_KEY": secret},
                config={"MODEL_NAME": "claude-sonnet"},
            )
        )
        script = tmp_path / "exfil_split.py"
        script.write_text(
            "import os, time\n"
            "val = os.environ['ANTHROPIC_API_KEY'].encode()\n"
            "# Write 3-byte chunks across separate OS write() syscalls with delays\n"
            "os.write(1, b'OUT_START:')\n"
            "os.write(2, b'ERR_START:')\n"
            "for i in range(0, len(val), 3):\n"
            "    os.write(1, val[i:i+3])\n"
            "    os.write(2, val[i:i+3])\n"
            "    time.sleep(0.002)\n"
            "os.write(1, b':END:' + os.environ['MODEL_NAME'].encode() + b'\\n')\n"
            "os.write(2, b':END\\n')\n",
            encoding="utf-8",
        )

        rc = run_with_secrets(
            ["anthropic_prod"],
            [sys.executable, str(script)],
            quiet=True,
        )
        captured = capsys.readouterr()
        stdout_data = captured.out
        stderr_data = captured.err

        assert rc == 0
        assert secret not in stdout_data
        assert secret[:8] not in stdout_data
        assert secret not in stderr_data
        assert secret[:8] not in stderr_data
        assert "OUT_START:<concealed by passkey>:END:claude-sonnet" in stdout_data
        assert "ERR_START:<concealed by passkey>:END" in stderr_data

    def test_json_escaped_secret_exfiltration_scrubbed_preserving_valid_json(self, tmp_path, capsys):
        # Secret contains quotes, backslashes, and newlines so JSON-RPC serializes it escaped
        complex_secret = 'sec_"quoted"\\back\nsecond_line_xyz987'
        escaped_secret = json.dumps(complex_secret)[1:-1]
        save_entry(
            Entry(
                name="mcp_child",
                fields={"MCP_TOKEN": complex_secret},
                config={"SERVICE_ID": "public-service-id"},
            )
        )
        script = tmp_path / "exfil_jsonrpc.py"
        script.write_text(
            "import json, os, sys\n"
            "payload = {\n"
            "    'jsonrpc': '2.0',\n"
            "    'id': 1,\n"
            "    'error': {\n"
            "        'code': -32000,\n"
            "        'message': 'Auth failed for ' + os.environ['MCP_TOKEN'],\n"
            "        'service': os.environ['SERVICE_ID'],\n"
            "    }\n"
            "}\n"
            "sys.stdout.write(json.dumps(payload) + '\\n')\n"
            "sys.stdout.flush()\n"
            "sys.stderr.write(json.dumps({'stderr_leak': os.environ['MCP_TOKEN']}) + '\\n')\n"
            "sys.stderr.flush()\n",
            encoding="utf-8",
        )

        rc = run_with_secrets(
            ["mcp_child"],
            [sys.executable, str(script)],
            quiet=True,
        )
        captured = capsys.readouterr()
        stdout_text = captured.out.strip()
        stderr_text = captured.err.strip()

        assert rc == 0
        assert complex_secret not in stdout_text
        assert escaped_secret not in stdout_text
        assert "second_line_xyz987" not in stdout_text
        assert complex_secret not in stderr_text
        assert escaped_secret not in stderr_text

        # JSON-RPC framing must still parse cleanly after replacement
        parsed_rpc = json.loads(stdout_text)
        assert parsed_rpc["error"]["message"] == "Auth failed for <concealed by passkey>"
        assert parsed_rpc["error"]["service"] == "public-service-id"
        parsed_err = json.loads(stderr_text)
        assert parsed_err["stderr_leak"] == "<concealed by passkey>"


class TestRedTeamPipedExportBlocking:
    """Scenario 2: Non-TTY piped `printf 'y\\n' | passkey export -` blocked before keychain read."""

    def test_cmd_export_stdout_rejects_piped_non_tty_stdin(self, monkeypatch, capsys):
        secret_val = "ghp_TopSecretNeverPipeToStdout123456"
        save_entry(Entry(name="gh_secret", fields={"GITHUB_TOKEN": secret_val}))

        fake_pipe_stdin = io.StringIO("y\nyes\n")
        monkeypatch.setattr(sys, "stdin", fake_pipe_stdin)

        with pytest.raises(PasskeyError, match="interactive terminal"):
            cmd_export("-", no_secrets=False)

        captured = capsys.readouterr()
        assert secret_val not in captured.out
        assert secret_val not in captured.err

    def test_cli_subprocess_piped_export_dash_exits_nonzero_without_touching_keychain(
        self, isolated_data_dir
    ):
        env = dict(os.environ)
        env["PASSKEY_DATA_DIR"] = str(isolated_data_dir)
        proc = subprocess.run(
            [sys.executable, "-m", "passkey", "export", "-"],
            input="y\n",
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        assert proc.returncode != 0
        assert "interactive terminal" in proc.stderr


class TestRedTeamReferenceTraversalAndInjection:
    """Scenario 3: Traversal, reserved-key access, and shell/field injection in passkey:// URIs."""

    @pytest.mark.parametrize(
        "malicious_env",
        [
            "../etc/passwd",
            "../../private/etc/master.passwd",
            "nested/entry",
            "__audit_hmac_key__",
            "__lease_hmac_key__",
            "__entries__",
            "$(id)",
            "`whoami`",
            "prod; rm -rf /",
            "entry with spaces",
            "null\x00byte",
            "",
        ],
    )
    def test_malicious_env_interpolation_blocked_across_parser_inject_and_run(
        self, malicious_env, tmp_path
    ):
        # Ensure internal HMAC keys exist in keyring so an attacker might try to read them
        save_entry(Entry(name="legit_entry", fields={"TOKEN": "safe_tok_1234"}))
        log_operation("new", "legit_entry")
        grant_lease("legit_entry", ttl="60s")

        env_map = {"TARGET_ENV": malicious_env}
        with pytest.raises(PasskeyError):
            parse_reference("passkey://${TARGET_ENV}/TOKEN", env=env_map)

        # Also test via template injection (`passkey inject` / `render_template`)
        tpl = tmp_path / "config.tmpl"
        out = tmp_path / "config.out"
        tpl.write_text("secret = {{ passkey://${TARGET_ENV}/TOKEN }}\n", encoding="utf-8")
        if "\x00" not in malicious_env:
            with (
                patch.dict(os.environ, {"TARGET_ENV": malicious_env}, clear=False),
                pytest.raises(PasskeyError),
            ):
                cmd_inject(in_file=str(tpl), out_file=str(out))
            assert not out.exists()
        else:
            from passkey.references import render_template

            with pytest.raises(PasskeyError):
                render_template(tpl.read_text(encoding="utf-8"), env=env_map)

        # Also test via `passkey run --env-file`
        dotenv = tmp_path / ".env.passkey"
        dotenv.write_text("LEAKED=passkey://${TARGET_ENV}/TOKEN\n", encoding="utf-8")
        with pytest.raises(PasskeyError):
            run_with_secrets(
                [],
                [sys.executable, "-c", "pass"],
                env_files=[str(dotenv)],
                extra_env={"TARGET_ENV": malicious_env},
                quiet=True,
            )

    def test_variable_interpolation_in_field_segment_always_rejected(self, tmp_path):
        save_entry(Entry(name="app_prod", fields={"API_KEY": "prod_val_9999"}))
        with pytest.raises(PasskeyError, match="entry segment"):
            parse_reference("passkey://app_prod/${FIELD_NAME}", env={"FIELD_NAME": "API_KEY"})

        dotenv = tmp_path / ".env.tpl"
        dotenv.write_text("KEY=passkey://app_prod/${FIELD_NAME}\n", encoding="utf-8")
        res = passkey_validate_references(str(dotenv))
        assert res["valid"] is False
        assert res["missing"]


class TestRedTeamAuditAndLeaseHmacTampering:
    """Scenario 4: Cryptographic HMAC tamper detection on audit.log and leases.json."""

    def test_audit_log_detects_edit_deletion_and_unsigned_append(self, monkeypatch):
        log_operation("new", "alpha")
        log_operation("run", "beta")
        log_operation("get", "gamma")
        assert verify_audit_log()["valid"] is True

        audit_path = get_log_path()
        original_lines = audit_path.read_text(encoding="utf-8").splitlines()
        assert len(original_lines) == 3

        # 4a. Bit-flip in HMAC digest
        rec0 = json.loads(original_lines[0])
        flipped = ("0" if rec0["hmac"][0] != "0" else "1") + rec0["hmac"][1:]
        rec0["hmac"] = flipped
        audit_path.write_text(
            "\n".join([json.dumps(rec0), *original_lines[1:]]) + "\n", encoding="utf-8"
        )
        assert verify_audit_log()["valid"] is False
        with pytest.raises(PasskeyError, match="FAILED"):
            cmd_audit(verify=True)

        # 4b. Delete middle record (breaks prev_hmac link between line 1 and line 3)
        audit_path.write_text(
            "\n".join([original_lines[0], original_lines[2]]) + "\n", encoding="utf-8"
        )
        res_mid = verify_audit_log()
        assert res_mid["valid"] is False
        assert res_mid["failed_line"] == 2

        # 4c. Delete genesis record (line 2's prev_hmac != GENESIS)
        audit_path.write_text(
            "\n".join(original_lines[1:]) + "\n", encoding="utf-8"
        )
        res_head = verify_audit_log()
        assert res_head["valid"] is False
        assert res_head["failed_line"] == 1

        # 4d. Inject forged unsigned record at tail
        forged = json.dumps(
            {"timestamp": "2026-11-17T00:00:00+00:00", "operation": "export", "entry": "all"}
        )
        audit_path.write_text("\n".join([*original_lines, forged]) + "\n", encoding="utf-8")
        assert verify_audit_log()["valid"] is False

        # Doctor --deep must surface broken audit_integrity
        monkeypatch.setattr("passkey.doctor.find_passkey_command", lambda: "/usr/local/bin/passkey")
        report = run_diagnostics(deep=True)
        audit_checks = [c for c in report["checks"] if c["name"] == "audit_integrity"]
        assert audit_checks and audit_checks[0]["status"] == "fail"

    def test_leases_json_detects_privilege_escalation_and_signature_stripping(self):
        prod_entry = Entry(name="prod_vault", fields={"SECRET": "vault_999"}, policy="prompt")
        save_entry(prod_entry)
        save_entry(Entry(name="staging_vault", fields={"SECRET": "stg_111"}, policy="prompt"))
        grant_lease("staging_vault", ttl="5m", max_uses=1)

        leases_path = get_leases_path()
        original_doc = json.loads(leases_path.read_text(encoding="utf-8"))

        # Escalate entry name from staging_vault -> prod_vault while keeping old hmac
        escalated = json.loads(json.dumps(original_doc))
        escalated["leases"]["prod_vault"] = escalated["leases"].pop("staging_vault")
        escalated["leases"]["prod_vault"]["remaining_uses"] = 999
        leases_path.write_text(json.dumps(escalated), encoding="utf-8")

        with pytest.raises(PasskeyError, match="HMAC mismatch"):
            consume_lease("prod_vault")
        with pytest.raises(PasskeyError, match="HMAC mismatch"):
            list_leases()
        with pytest.raises(PasskeyError, match="HMAC mismatch"):
            authorize_entry_access(prod_entry)

        # Reset valid store, then strip hmac signature completely
        leases_path.unlink()
        grant_lease("prod_vault", ttl="5m", max_uses=2)
        stripped = json.loads(leases_path.read_text(encoding="utf-8"))
        stripped.pop("hmac", None)
        leases_path.write_text(json.dumps(stripped), encoding="utf-8")

        with pytest.raises(PasskeyError, match="integrity check failed"):
            consume_lease("prod_vault")


class TestRedTeamPhishingAndBrowserBroker:
    """Scenario 5: Phishing origin spoofing, scheme downgrade, and non-loopback CDP rejection."""

    @pytest.mark.parametrize(
        "phishing_origin",
        [
            "https://portal.example.com.evil.attacker",
            "https://evil-portal.example.com",
            "https://sub.portal.example.com",
            "http://portal.example.com",
            "https://portal.example.com:8443",
            "about:blank",
            "javascript:alert(1)",
        ],
    )
    def test_phishing_origins_never_receive_credentials_or_prompt_auth(self, phishing_origin):
        save_entry(
            Entry(
                name="okta_admin",
                fields={
                    "USERNAME": "admin@example.com",
                    "PASSWORD": "SuperSensitiveAdminPassword!",
                    "SESSION_COOKIE": "okta_sid_secret_value",
                },
                config={"ORIGIN": "https://portal.example.com"},
                policy="prompt",
            )
        )
        with (
            _MockCDPServer(phishing_origin) as srv,
            patch("passkey.auth.authenticate") as mock_auth,
            pytest.raises(PasskeyError),
        ):
            cdp_autofill("okta_admin", f"ws://127.0.0.1:{srv.port}/devtools/page/tab1")

        # Biometric prompt must NOT even fire when origin doesn't match
        mock_auth.assert_not_called()
        # Zero credential-injecting CDP calls may have been sent
        methods = [c["method"] for c in srv.received_calls]
        assert "Input.insertText" not in methods
        assert "Network.setCookie" not in methods

    @pytest.mark.parametrize(
        "bad_cdp_url",
        [
            "ws://evil.example.com:9222/devtools/page/1",
            "ws://10.0.0.42:9222/devtools/page/1",
            "wss://127.0.0.1:9222/devtools/page/1",
            "file:///etc/passwd",
        ],
    )
    def test_remote_or_invalid_cdp_endpoints_blocked_and_mcp_gate_enforced(self, bad_cdp_url):
        save_entry(
            Entry(
                name="okta_admin",
                fields={"PASSWORD": "SuperSensitiveAdminPassword!"},
                config={"ORIGIN": "https://portal.example.com"},
            )
        )
        with pytest.raises(PasskeyError):
            cdp_autofill("okta_admin", bad_cdp_url)

        # MCP tool is locked off by default
        set_setting("mcp_browser_broker", False)
        mcp_res = passkey_cdp_autofill("okta_admin", "ws://127.0.0.1:9222")
        assert mcp_res["filled"] is False
        assert "SuperSensitiveAdminPassword!" not in json.dumps(mcp_res)


class TestRedTeamMcpWriteLockAndPathTraversal:
    """Scenario 6: D3-4 mcp_write_tools lock and macOS /private/etc & /private/var traversal."""

    def test_passkey_wrap_server_blocked_when_mcp_write_tools_disabled(self, tmp_path):
        save_entry(Entry(name="github", fields={"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz1234"}))
        cfg = tmp_path / "mcp.json"
        original_content = json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                        "env": {"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz1234"},
                    }
                }
            }
        )
        cfg.write_text(original_content, encoding="utf-8")

        set_setting("mcp_write_tools", False)
        res = passkey_wrap_server("github", config_paths=[str(cfg)])
        assert res["success"] is False
        assert "disabled" in res["message"].lower()
        # Config file must remain completely untouched
        assert cfg.read_text(encoding="utf-8") == original_content

    @pytest.mark.parametrize(
        "forbidden_path",
        [
            "/etc/mcp.json",
            "/private/etc/mcp.json",
            "/private/etc/pam.d/sudo",
            "/tmp/../etc/mcp.json",
            "/tmp/../../private/etc/mcp.json",
            "/private/var/root/mcp.json",
            "/private/var/db/ConfigurationProfiles/mcp.json",
        ],
    )
    def test_macos_private_etc_and_private_var_rejected_by_mcp_tools(self, forbidden_path):
        save_entry(Entry(name="srv", fields={"API_KEY": "secret_key_12345"}))
        assert _validate_config_paths([forbidden_path]) == []

        set_setting("mcp_write_tools", True)
        wrap_res = passkey_wrap_server("srv", config_paths=[forbidden_path])
        assert wrap_res["success"] is False
        assert "no config files found" in wrap_res["message"].lower()

        ref_res = passkey_validate_references(forbidden_path)
        assert ref_res["valid"] is False
        assert ref_res["missing"]
