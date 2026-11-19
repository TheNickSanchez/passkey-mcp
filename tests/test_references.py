"""Tests for Wave 2 passkey:// reference URIs, --env-file, passkey inject, and MCP validation."""

import io
import sys

import pytest

from passkey.commands import cmd_inject
from passkey.keychain import PasskeyError, save_entry
from passkey.masking import CONCEALED_TEXT
from passkey.mcp_server import passkey_validate_references
from passkey.models import Entry
from passkey.references import parse_reference, render_template, resolve_reference
from passkey.runner import run_with_secrets


class TestReferenceParsingAndResolution:
    """Tests for passkey://<entry>/<field> parsing, interpolation, and security bounds."""

    def test_parses_canonical_reference_and_interpolates_entry_only(self):
        entry_name, field_name = parse_reference(
            "passkey://${APP_ENV}_db/DB_PASSWORD",
            env={"APP_ENV": "staging"},
        )
        assert entry_name == "staging_db"
        assert field_name == "DB_PASSWORD"

    @pytest.mark.parametrize(
        "bad_uri,env",
        [
            ("http://prod/TOKEN", {}),
            ("passkey://prod", {}),
            ("passkey://prod/a/b", {}),
            ("passkey://../etc/TOKEN", {}),
            ("passkey://${BAD}/TOKEN", {"BAD": "../secret"}),
            ("passkey://${BAD}/TOKEN", {"BAD": "__audit_hmac_key__"}),
            ("passkey://prod/${INJECT_FIELD}", {"INJECT_FIELD": "TOKEN"}),
            ("passkey://$(whoami)/TOKEN", {}),
        ],
    )
    def test_rejects_malformed_or_traversal_references(self, bad_uri, env):
        with pytest.raises(PasskeyError):
            parse_reference(bad_uri, env=env)

    def test_resolves_secret_and_config_fields(self):
        save_entry(
            Entry(
                name="stripe_prod",
                fields={"SECRET_KEY": "sk_live_abcdefghijklmno"},
                config={"WEBHOOK_PORT": "8443"},
            )
        )
        sec_val, is_sec = resolve_reference("passkey://stripe_prod/SECRET_KEY")
        assert sec_val == "sk_live_abcdefghijklmno"
        assert is_sec is True

        cfg_val, is_sec_cfg = resolve_reference("passkey://stripe_prod/WEBHOOK_PORT")
        assert cfg_val == "8443"
        assert is_sec_cfg is False


class TestRunEnvFileAndInject:
    """Tests for passkey run --env-file, inherited reference resolution, and passkey inject."""

    def test_run_resolves_env_file_and_inherited_references_with_masking(
        self, tmp_path, monkeypatch, capsys
    ):
        save_entry(
            Entry(
                name="github_prod",
                fields={"PAT": "ghp_supersecret9988776655"},
                config={"API_HOST": "api.github.com"},
            )
        )
        env_file = tmp_path / ".env.passkey"
        env_file.write_text(
            "# Safe committable reference file\n"
            "CUSTOM_GH_TOKEN=passkey://github_prod/PAT\n"
            "GH_HOST=passkey://github_prod/API_HOST\n"
        )
        monkeypatch.setenv("INHERITED_SECRET", "passkey://github_prod/PAT")

        script = (
            "import os, sys; "
            "assert os.environ['CUSTOM_GH_TOKEN'] == os.environ['INHERITED_SECRET']; "
            "sys.stdout.write(os.environ['CUSTOM_GH_TOKEN'] + '|' + os.environ['GH_HOST'] + '\\n')"
        )
        rc = run_with_secrets(
            [],
            [sys.executable, "-c", script],
            quiet=True,
            env_files=[str(env_file)],
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "ghp_supersecret9988776655" not in out
        assert f"{CONCEALED_TEXT}|api.github.com" in out

    def test_cmd_inject_writes_atomic_0600_and_refuses_non_tty_stdout(self, tmp_path, monkeypatch):
        save_entry(Entry(name="db", fields={"PASS": "db_s3cr3t_9999"}))
        tpl = tmp_path / "config.yml.tpl"
        tpl.write_text("password: {{ passkey://db/PASS }}\n")
        out_path = tmp_path / "config.yml"

        cmd_inject(str(tpl), str(out_path))
        assert out_path.read_text() == "password: db_s3cr3t_9999\n"
        assert oct(out_path.stat().st_mode & 0o777) == "0o600"

        # Refuses overwrite without --force
        with pytest.raises(PasskeyError, match="already exists"):
            cmd_inject(str(tpl), str(out_path))

        # Refuses stdout without --stdout
        with pytest.raises(PasskeyError, match="--stdout"):
            cmd_inject(str(tpl), None, to_stdout=False)

        # Refuses --stdout when stdin/stdout is not a TTY
        monkeypatch.setattr(sys, "stdin", io.StringIO(""))
        with pytest.raises(PasskeyError, match="interactive terminal"):
            cmd_inject(str(tpl), None, to_stdout=True)

    def test_mcp_validate_references_never_leaks_secret_values(self, tmp_path):
        secret_value = "ultra_secret_never_in_mcp_output"
        save_entry(Entry(name="payments", fields={"API_KEY": secret_value}))

        valid_file = tmp_path / ".env.passkey"
        valid_file.write_text("PAYMENTS_KEY=passkey://payments/API_KEY\n")
        ok_res = passkey_validate_references(str(valid_file))
        assert ok_res == {
            "valid": True,
            "checked": 1,
            "missing": [],
            "prompt_entries_without_lease": [],
            "will_prompt_biometric": False,
        }
        assert secret_value not in str(ok_res)

        broken_file = tmp_path / "broken.tpl"
        broken_file.write_text(
            "a={{ passkey://payments/API_KEY }}\n"
            "b={{ passkey://payments/MISSING_FIELD }}\n"
            "c={{ passkey://missing_entry/KEY }}\n"
        )
        bad_res = passkey_validate_references(str(broken_file))
        assert bad_res["valid"] is False
        assert bad_res["checked"] == 3
        assert len(bad_res["missing"]) == 2
        assert secret_value not in str(bad_res)
        assert render_template("x={{ passkey://payments/API_KEY }}") == f"x={secret_value}"
