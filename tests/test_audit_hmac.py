"""Tests for Wave 2 caller attribution and HMAC-SHA256 hash-chained audit logs."""

import json

import pytest

import passkey.audit as audit_mod
from passkey.audit import GENESIS_HMAC, log_operation, verify_audit_log
from passkey.commands import cmd_audit
from passkey.doctor import run_diagnostics
from passkey.keychain import PasskeyError
from passkey.mcp_server import passkey_audit_recent


class TestAuditAttributionAndHmacChain:
    """Tests for actor attribution, HMAC chain verification, rotation, and sanitization."""

    def test_hmac_chain_links_records_and_verifies(self, isolated_data_dir, monkeypatch):
        monkeypatch.setenv("CLAUDECODE", "1")
        log_operation("create", "stripe", {"field_count": 2}, argv0="/usr/local/bin/passkey")
        log_operation("read", "stripe")
        log_operation("run", "stripe", {"entries": ["stripe"]}, argv0="/usr/bin/python3")

        log_path = audit_mod.get_log_path()
        records = [json.loads(ln) for ln in log_path.read_text().splitlines() if ln.strip()]
        assert len(records) == 3
        assert records[0]["prev_hmac"] == GENESIS_HMAC
        assert records[1]["prev_hmac"] == records[0]["hmac"]
        assert records[2]["prev_hmac"] == records[1]["hmac"]

        assert records[0]["actor"]["type"] == "agent"
        assert records[0]["actor"]["client"] == "claude-code"
        assert records[0]["argv0"] == "passkey"
        assert records[2]["argv0"] == "python3"

        ver = verify_audit_log()
        assert ver == {"valid": True, "checked": 3, "error": None, "failed_line": None}

    def test_detects_field_tampering_and_line_deletion(self, isolated_data_dir):
        log_operation("create", "a")
        log_operation("read", "b")
        log_operation("delete", "c")

        log_path = audit_mod.get_log_path()
        original_lines = log_path.read_text().splitlines()

        # 1. Tamper with middle record's entry name
        tampered = json.loads(original_lines[1])
        tampered["entry"] = "forged"
        log_path.write_text(
            "\n".join([original_lines[0], json.dumps(tampered), original_lines[2]]) + "\n"
        )
        ver_tampered = verify_audit_log()
        assert ver_tampered["valid"] is False
        assert ver_tampered["failed_line"] == 2

        with pytest.raises(PasskeyError, match="FAILED"):
            cmd_audit(verify=True)

        # 2. Delete the first line (prefix truncation without HMAC key)
        log_path.write_text("\n".join(original_lines[1:]) + "\n")
        ver_deleted = verify_audit_log()
        assert ver_deleted["valid"] is False
        assert ver_deleted["failed_line"] == 1

    def test_atomic_rotation_preserves_valid_hmac_chain(self, isolated_data_dir, monkeypatch):
        for i in range(8):
            log_operation("read", f"entry-{i}")

        monkeypatch.setattr(audit_mod, "MAX_LOG_BYTES", 400)
        log_operation("read", "after-rotation")

        ver = verify_audit_log()
        assert ver["valid"] is True
        assert ver["checked"] >= 4

    def test_doctor_deep_and_mcp_audit_recent_sanitization(self, isolated_data_dir, monkeypatch):
        log_operation(
            "read",
            "github",
            details={
                "field_count": 1,
                "error": "sensitive_raw_exception_string_do_not_expose",
            },
            success=False,
        )
        recent = passkey_audit_recent(limit=5)
        assert len(recent) == 1
        rec = recent[0]
        assert rec["entry"] == "github"
        assert "hmac" not in rec
        assert "prev_hmac" not in rec
        assert "sensitive_raw_exception_string_do_not_expose" not in json.dumps(rec)
        assert rec["details"] == {"field_count": 1}

        monkeypatch.setattr("passkey.doctor.find_passkey_command", lambda: "/usr/local/bin/passkey")
        diag = run_diagnostics(deep=True)
        assert any(c["name"] == "audit_integrity" and c["status"] == "pass" for c in diag["checks"])
