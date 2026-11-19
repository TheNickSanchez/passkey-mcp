"""Tests for v0.8.0 Milestone 1: Structured Error Codes & JSON Error Envelopes."""

import json
import sys
from unittest.mock import patch

import pytest

from passkey.cli import main
from passkey.keychain import KeychainAccessError, PasskeyError, save_entry
from passkey.models import Entry


class TestStructuredErrorEnvelopes:
    """Verify --json and PASSKEY_OUTPUT=json emit deterministic error envelopes without leaks."""

    def test_info_missing_entry_json_envelope(self, capsys):
        with (
            patch("passkey.interactive.is_interactive", return_value=False),
            patch.object(sys, "argv", ["passkey", "info", "stripe_dev", "--json"]),
            pytest.raises(SystemExit) as exc,
        ):
            main()

        assert exc.value.code == 1
        data = json.loads(capsys.readouterr().out)
        assert data["ok"] is False
        assert data["error_code"] == "ENTRY_NOT_FOUND"
        assert data["entry"] == "stripe_dev"
        assert data["remediation_command"] == "passkey new stripe_dev"

    def test_passkey_output_env_enables_json_happy_and_error_paths(self, monkeypatch, capsys):
        monkeypatch.setenv("PASSKEY_OUTPUT", "json")
        secret_val = "sk_live_ERROR_ENVELOPE_NEVER_LEAK"
        save_entry(Entry(name="stripe", fields={"STRIPE_SECRET_KEY": secret_val}, policy="prompt"))

        # 1. Happy path without --json flag emits JSON automatically
        with patch.object(sys, "argv", ["passkey", "list"]):
            main()
        listed = json.loads(capsys.readouterr().out)
        assert len(listed) == 1
        assert listed[0]["name"] == "stripe"
        assert secret_val not in json.dumps(listed)

        # 2. Interactive command in non-TTY emits INTERACTIVE_REQUIRED JSON (exit 2)
        with (
            patch("passkey.interactive.is_interactive", return_value=False),
            patch.object(sys, "argv", ["passkey", "get", "stripe"]),
            pytest.raises(SystemExit) as exc_int,
        ):
            main()
        assert exc_int.value.code == 2
        err_int = json.loads(capsys.readouterr().out)
        assert err_int["ok"] is False
        assert err_int["error_code"] == "INTERACTIVE_REQUIRED"
        assert err_int["entry"] == "stripe"
        assert "passkey info stripe --json" in err_int["remediation_command"]
        assert secret_val not in json.dumps(err_int)

        # 3. Unknown command typo emits UNKNOWN_COMMAND JSON
        with patch.object(sys, "argv", ["passkey", "stauts"]), pytest.raises(SystemExit) as exc_cmd:
            main()
        assert exc_cmd.value.code == 1
        err_cmd = json.loads(capsys.readouterr().out)
        assert err_cmd["ok"] is False
        assert err_cmd["error_code"] == "UNKNOWN_COMMAND"
        assert err_cmd["remediation_command"] == "passkey status"

    def test_run_child_wrapping_errors_emit_json_on_stderr_preserving_stdout(
        self, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setenv("PASSKEY_OUTPUT", "json")
        secret_val = "sk_live_BIOMETRIC_SECRET_999"
        save_entry(
            Entry(name="prod_db", fields={"DATABASE_URL": secret_val}, policy="prompt")
        )

        # 1. Biometric denial during `passkey run` writes JSON envelope to stderr, leaving stdout clean
        with (
            patch("passkey.auth.authenticate", return_value=False),
            patch.object(
                sys, "argv", ["passkey", "run", "-q", "prod_db", "--", sys.executable, "-c", "pass"]
            ),
            pytest.raises(SystemExit) as exc_bio,
        ):
            main()
        assert exc_bio.value.code == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        err_bio = json.loads(captured.err)
        assert err_bio["ok"] is False
        assert err_bio["error_code"] == "BIOMETRIC_DENIED"
        assert err_bio["entry"] == "prod_db"
        assert "passkey lease grant prod_db" in err_bio["remediation_command"]
        assert secret_val not in captured.err

        # 2. Missing referenced field in --env-file preserves MISSING_FIELD + missing_fields
        save_entry(Entry(name="email_svc", fields={"EXISTING_KEY": "val_1234"}))
        env_file = tmp_path / ".env.passkey"
        env_file.write_text("RESEND_KEY=passkey://email_svc/RESEND_API_KEY\n", encoding="utf-8")

        with (
            patch.object(
                sys,
                "argv",
                [
                    "passkey",
                    "run",
                    "-q",
                    "--env-file",
                    str(env_file),
                    "--",
                    sys.executable,
                    "-c",
                    "pass",
                ],
            ),
            pytest.raises(SystemExit) as exc_mf,
        ):
            main()
        assert exc_mf.value.code == 1
        cap_mf = capsys.readouterr()
        assert cap_mf.out == ""
        err_mf = json.loads(cap_mf.err)
        assert err_mf["ok"] is False
        assert err_mf["error_code"] == "MISSING_FIELD"
        assert err_mf["entry"] == "email_svc"
        assert err_mf["missing_fields"] == ["RESEND_API_KEY"]
        assert err_mf["remediation_command"] == "passkey entry set-field email_svc RESEND_API_KEY"

    def test_keychain_error_subclass_default_code(self):
        err = KeychainAccessError("Keychain locked")
        assert isinstance(err, PasskeyError)
        assert err.to_error_dict() == {
            "ok": False,
            "error_code": "KEYCHAIN_ACCESS_ERROR",
            "message": "Keychain locked",
        }
