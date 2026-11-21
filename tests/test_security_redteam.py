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


class TestRedTeamMetadataIndexTamperingAndZeroLeakage:
    """Scenario 7: Tampering with entries.json policy cannot bypass Keychain policy at secret release."""

    def test_entries_json_contains_zero_values_and_policy_tampering_cannot_bypass_auth(
        self, tmp_path, isolated_data_dir, monkeypatch
    ):
        from passkey.keychain import _get_index_path, get_entry_meta
        from passkey.project import exec_with_project, trust_project

        secret_value = "sk_live_ULTRA_SENSITIVE_PROD_KEY_8888"
        config_value = "https://vault-internal.corp.secret.example"
        save_entry(
            Entry(
                name="prod_payments",
                fields={"STRIPE_SECRET_KEY": secret_value},
                config={"INTERNAL_ENDPOINT": config_value},
                policy="prompt",
            )
        )

        # 1. Verify entries.json on disk is 0o600 and contains zero secret or config values
        idx_path = _get_index_path()
        raw_index = idx_path.read_text(encoding="utf-8")
        if sys.platform != "win32":
            assert (idx_path.stat().st_mode & 0o777) == 0o600
        assert secret_value not in raw_index
        assert config_value not in raw_index

        # 2. Attacker manually edits entries.json on disk: downgrades "policy": "prompt" -> "allow"
        tampered_doc = json.loads(raw_index)
        assert tampered_doc["entries"]["prod_payments"]["policy"] == "prompt"
        tampered_doc["entries"]["prod_payments"]["policy"] = "allow"
        idx_path.write_text(json.dumps(tampered_doc, indent=2), encoding="utf-8")

        # Cached metadata reflects the local file, NOT authoritative Keychain policy
        cached = get_entry_meta("prod_payments")
        assert cached is not None and cached.policy == "allow"

        # 3a. run_with_secrets MUST read authoritative Keychain Entry (policy="prompt") and block!
        marker_file = tmp_path / "pwned_child_ran.txt"
        with (
            patch("passkey.auth.authenticate", return_value=False) as mock_auth,
            pytest.raises(PasskeyError) as exc_run,
        ):
            run_with_secrets(
                ["prod_payments"],
                [
                    sys.executable,
                    "-c",
                    f"import pathlib; pathlib.Path({str(marker_file)!r}).write_text('pwned')",
                ],
                quiet=True,
            )
        assert exc_run.value.error_code == "BIOMETRIC_DENIED"
        mock_auth.assert_called_once()
        assert not marker_file.exists()

        # Reading from Keychain automatically self-heals the tampered entries.json policy back to "prompt"
        repaired_meta = get_entry_meta("prod_payments")
        assert repaired_meta is not None and repaired_meta.policy == "prompt"
        assert json.loads(idx_path.read_text(encoding="utf-8"))["entries"]["prod_payments"]["policy"] == "prompt"

        # Re-tamper entries.json before testing cmd_inject and exec_with_project
        tampered_doc["entries"]["prod_payments"]["policy"] = "allow"
        idx_path.write_text(json.dumps(tampered_doc, indent=2), encoding="utf-8")

        # 3b. cmd_inject MUST read authoritative Keychain Entry (policy="prompt") and block!
        tpl_path = tmp_path / "secret.tpl"
        out_path = tmp_path / "secret.out"
        tpl_path.write_text("KEY={{ passkey://prod_payments/STRIPE_SECRET_KEY }}\n", encoding="utf-8")
        with (
            patch("passkey.auth.authenticate", return_value=False) as mock_auth_inj,
            pytest.raises(PasskeyError) as exc_inj,
        ):
            cmd_inject(str(tpl_path), str(out_path))
        assert exc_inj.value.error_code == "BIOMETRIC_DENIED"
        mock_auth_inj.assert_called_once()
        assert not out_path.exists()

        # 3c. exec_with_project (dry_run=False) MUST also enforce authoritative Keychain policy!
        repo = tmp_path / "trusted_repo"
        (repo / ".git").mkdir(parents=True)
        (repo / ".env.passkey").write_text(
            "STRIPE_SECRET_KEY=passkey://prod_payments/STRIPE_SECRET_KEY\n",
            encoding="utf-8",
        )
        monkeypatch.setattr("passkey.project.can_prompt_interactively", lambda: True)
        trust_project(repo)

        with (
            patch("passkey.auth.authenticate", return_value=False) as mock_auth_exec,
            pytest.raises(PasskeyError) as exc_exec,
        ):
            exec_with_project([sys.executable, "-c", "pass"], project_dir=repo, quiet=True)
        assert exc_exec.value.error_code == "BIOMETRIC_DENIED"
        mock_auth_exec.assert_called_once()

    def test_policies_json_tamper_rollback_and_deletion_blocked_and_surfaced_by_doctor(
        self, tmp_path, isolated_data_dir, capsys
    ):
        from passkey.cli import main
        from passkey.doctor import run_diagnostics
        from passkey.keychain import _get_index_path, get_entry_meta, get_policies_path
        from passkey.leases import authorize_entry_access
        from passkey.mcp_config import ADAPTERS

        # Originally saved with policy="allow" inside the Keychain secret payload
        save_entry(
            Entry(
                name="prod_jamf",
                fields={"JAMF_CLIENT_SECRET": "jamf_ultra_secret_9999"},
                policy="allow",
            )
        )

        # Snapshot 1: valid policies.json where prod_jamf = 'allow' (signed under __policy_hmac_key__)
        with patch.object(sys, "argv", ["passkey", "policy", "prod_jamf", "allow", "--json"]):
            main()
        capsys.readouterr()
        pol_path = get_policies_path()
        snapshot_allow_bytes = pol_path.read_bytes()

        # Upgrade prod_jamf to 'prompt' via zero-Keychain policy command (raw Keychain secret payload STILL has 'allow'!)
        with patch.object(sys, "argv", ["passkey", "policy", "prod_jamf", "prompt", "--json"]):
            main()
        capsys.readouterr()
        snapshot_prompt_bytes = pol_path.read_bytes()

        # Baseline: doctor --deep reports policy_integrity == 'pass'
        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
        ):
            diag_ok = run_diagnostics(deep=True)
        assert any(
            c["name"] == "policy_integrity" and c["status"] == "pass" for c in diag_ok["checks"]
        )

        marker = tmp_path / "should_never_run.txt"
        child_cmd = [
            sys.executable,
            "-c",
            f"import pathlib; pathlib.Path({str(marker)!r}).write_text('pwned')",
        ]

        # Attack A: Direct edit of policies.json ('prompt' -> 'allow') -> HMAC mismatch!
        tampered = json.loads(snapshot_prompt_bytes.decode("utf-8"))
        tampered["policies"]["prod_jamf"] = "allow"
        pol_path.write_text(json.dumps(tampered, indent=2), encoding="utf-8")

        with pytest.raises(PasskeyError) as exc_tamper:
            run_with_secrets(["prod_jamf"], child_cmd, quiet=True)
        assert exc_tamper.value.error_code == "POLICY_STORE_TAMPERED"
        assert not marker.exists()

        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
        ):
            diag_tamper = run_diagnostics(deep=True)
        assert diag_tamper["summary"]["failed"] > 0
        assert any(
            c["name"] == "policy_integrity" and c["status"] == "fail"
            for c in diag_tamper["checks"]
        )

        # Attack B: Rollback / Replay attack (replay older valid HMAC-signed snapshot_allow_bytes!)
        pol_path.write_bytes(snapshot_allow_bytes)

        with pytest.raises(PasskeyError) as exc_rollback:
            run_with_secrets(["prod_jamf"], child_cmd, quiet=True)
        assert exc_rollback.value.error_code == "POLICY_STORE_TAMPERED"
        assert "rollback" in str(exc_rollback.value).lower()
        assert not marker.exists()

        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
        ):
            diag_rollback = run_diagnostics(deep=True)
        assert any(
            c["name"] == "policy_integrity" and c["status"] == "fail"
            for c in diag_rollback["checks"]
        )

        # Attack C: Deletion attack (rm <data_dir>/policies.json)
        pol_path.unlink()
        assert not pol_path.exists()

        # Even if caller passes Entry(policy="allow") from the older Keychain payload,
        # authorize_entry_access detects Keychain anchor count > 0 with missing policies.json!
        with pytest.raises(PasskeyError) as exc_del_direct:
            authorize_entry_access(Entry(name="prod_jamf", fields={"K": "V"}, policy="allow"))
        assert exc_del_direct.value.error_code == "POLICY_STORE_TAMPERED"
        assert "deletion" in str(exc_del_direct.value).lower()

        with pytest.raises(PasskeyError) as exc_del_run:
            run_with_secrets(["prod_jamf"], child_cmd, quiet=True)
        assert exc_del_run.value.error_code == "POLICY_STORE_TAMPERED"
        assert not marker.exists()

        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
        ):
            diag_del = run_diagnostics(deep=True)
        assert any(
            c["name"] == "policy_integrity" and c["status"] == "fail"
            for c in diag_del["checks"]
        )

        # Attack D: Restore valid snapshot_prompt_bytes, tamper entries.json -> enforced & self-healed!
        pol_path.write_bytes(snapshot_prompt_bytes)
        idx_path = _get_index_path()
        idx_doc = json.loads(idx_path.read_text(encoding="utf-8"))
        idx_doc["entries"]["prod_jamf"]["policy"] = "allow"
        idx_path.write_text(json.dumps(idx_doc, indent=2), encoding="utf-8")
        assert get_entry_meta("prod_jamf").policy == "allow"

        with (
            patch("passkey.auth.authenticate", return_value=False) as mock_auth,
            pytest.raises(PasskeyError) as exc_bio,
        ):
            run_with_secrets(["prod_jamf"], child_cmd, quiet=True)
        assert exc_bio.value.error_code == "BIOMETRIC_DENIED"
        mock_auth.assert_called_once()
        assert not marker.exists()
        # Self-healed entries.json back to 'prompt' from verified policies.json!
        assert get_entry_meta("prod_jamf").policy == "prompt"

    def test_single_policy_fails_closed_while_authenticated_policy_all_reanchors_cleanly(
        self, isolated_data_dir, capsys
    ):
        from passkey.cli import main
        from passkey.doctor import run_diagnostics
        from passkey.keychain import get_entry, get_entry_meta, get_policies_path, set_entry_policy
        from passkey.mcp_config import ADAPTERS

        save_entry(Entry(name="prod_aws", fields={"AWS_KEY": "aws_sec"}, source="manual", policy="allow"))
        save_entry(
            Entry(name="bg_mcp", fields={"MCP_KEY": "mcp_sec"}, source="cursor-init", policy="allow")
        )

        set_entry_policy("prod_aws", "prompt")
        pol_path = get_policies_path()
        pol_path.unlink()  # Delete policies.json while .policies_initialized & Keychain anchor exist!

        # 1. Interactive read helper get_entry() also catches rm policies.json via is_policy_store_initialized()
        with pytest.raises(PasskeyError) as exc_get:
            get_entry("prod_aws")
        assert exc_get.value.error_code == "POLICY_STORE_TAMPERED"

        # 2. Single-entry set_entry_policy fails closed with exact remediation_command
        with pytest.raises(PasskeyError) as exc_single:
            set_entry_policy("prod_aws", "session")
        assert exc_single.value.error_code == "POLICY_STORE_TAMPERED"
        assert exc_single.value.remediation_command == "passkey policy --all session"
        assert "passkey policy --all" in str(exc_single.value)

        # 3. Doctor --deep recommends 'passkey policy --all session' recovery
        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
        ):
            diag_bad = run_diagnostics(deep=True)
        assert diag_bad["summary"]["failed"] > 0
        assert any("passkey policy --all session" in r for r in diag_bad["recommendations"])

        # 4. Unapproved OS auth blocks --all recovery
        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.auth.authenticate", return_value=False) as mock_deny,
            patch.object(
                sys,
                "argv",
                ["passkey", "policy", "--all", "session", "--exclude-mcp", "--yes", "--json"],
            ),
            pytest.raises(SystemExit) as exc_denied,
        ):
            main()
        assert exc_denied.value.code == 1
        mock_deny.assert_called_once()
        capsys.readouterr()

        # 5. Approved OS auth via require_auth rebuilds policies.json cleanly & returns doctor to green!
        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.auth.require_auth") as mock_req_auth,
            patch.object(
                sys,
                "argv",
                ["passkey", "policy", "--all", "session", "--exclude-mcp", "--yes", "--json"],
            ),
        ):
            main()
        mock_req_auth.assert_called_once_with("rebuild corrupted or tampered policies.json")
        rec_out = json.loads(capsys.readouterr().out)
        assert rec_out["ok"] is True
        assert rec_out["updated"] == ["prod_aws"]
        assert rec_out["excluded_mcp"] == ["bg_mcp"]
        assert pol_path.is_file()
        assert get_entry_meta("prod_aws").policy == "session"
        assert get_entry_meta("bg_mcp").policy == "allow"
        assert get_entry("prod_aws").policy == "session"

        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
        ):
            diag_recovered = run_diagnostics(deep=True)
        assert diag_recovered["summary"]["failed"] == 0
        assert any(
            c["name"] == "policy_integrity" and c["status"] == "pass"
            for c in diag_recovered["checks"]
        )
