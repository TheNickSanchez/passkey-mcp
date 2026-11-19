"""Tests for v0.8.0 Milestone 3: Project manifests, HMAC trust guard, and passkey exec."""

import json
import sys
from unittest.mock import patch

import pytest

from passkey.cli import main
from passkey.keychain import PasskeyError, save_entry
from passkey.masking import CONCEALED_TEXT
from passkey.mcp_server import passkey_project_status
from passkey.models import Entry
from passkey.plugins import init_plugin
from passkey.project import (
    discover_project_manifest,
    get_project_status,
    get_trusted_projects_path,
    init_project,
    trust_project,
)


class TestProjectManifestAndTrustGuard:
    """Verify passkey project init|status|trust, HMAC verification, and passkey exec."""

    def test_project_init_maps_vars_preserves_plugins_and_refuses_dotenv(
        self, tmp_path, monkeypatch, capsys
    ):
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)

        secret_stripe = "sk_test_project_init_never_written_999"
        secret_gh = "ghp_project_init_never_written_888"
        save_entry(
            Entry(
                name="stripe_dev",
                fields={"STRIPE_SECRET_KEY": secret_stripe},
                config={"STRIPE_REGION": "us-east-1"},
            )
        )
        save_entry(Entry(name="github", fields={"GITHUB_TOKEN": secret_gh}))

        # Bind a dir-scoped plugin first to verify .passkey.toml preserves [plugins]
        init_plugin("gh", entry_name="github", scope="dir", project_dir=repo)

        (repo / ".env.example").write_text(
            "STRIPE_SECRET_KEY=sk_placeholder\n"
            "STRIPE_REGION=us-west-2\n"
            "GH_TOKEN=ghp_placeholder\n"
            "MISSING_WEBHOOK_SECRET=\n",
            encoding="utf-8",
        )
        (repo / ".env").write_text("STRIPE_SECRET_KEY=real_secret\n", encoding="utf-8")

        # Refuses live .env
        with pytest.raises(PasskeyError) as exc_env:
            init_project(project_dir=repo, from_file=".env")
        assert exc_env.value.error_code == "SENSITIVE_FILE_REFUSED"

        # Agent-initiated init (non-interactive) generates manifest WITHOUT auto-trusting
        monkeypatch.setenv("CLAUDECODE", "1")
        with patch.object(
            sys,
            "argv",
            [
                "passkey",
                "project",
                "init",
                "--project-dir",
                str(repo),
                "--entries",
                "stripe_dev",
                "--json",
            ],
        ):
            main()

        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is True
        assert payload["trusted"] is False
        assert payload["mapped_vars"] == {
            "STRIPE_SECRET_KEY": "passkey://stripe_dev/STRIPE_SECRET_KEY",
            "STRIPE_REGION": "passkey://stripe_dev/STRIPE_REGION",
            "GH_TOKEN": "passkey://github/GITHUB_TOKEN",
        }
        assert payload["missing_vars"] == ["MISSING_WEBHOOK_SECRET"]

        env_passkey_text = (repo / ".env.passkey").read_text(encoding="utf-8")
        assert secret_stripe not in env_passkey_text
        assert secret_gh not in env_passkey_text
        assert "STRIPE_SECRET_KEY=passkey://stripe_dev/STRIPE_SECRET_KEY" in env_passkey_text
        assert "GH_TOKEN=passkey://github/GITHUB_TOKEN" in env_passkey_text

        toml_text = (repo / ".passkey.toml").read_text(encoding="utf-8")
        assert "[project]" in toml_text
        assert "[plugins]" in toml_text
        assert 'gh = "github"' in toml_text

    def test_exec_blocks_untrusted_then_runs_from_subdir_with_secret_masking(
        self, tmp_path, monkeypatch, capsys
    ):
        repo = tmp_path / "app"
        subdir = repo / "packages" / "api"
        (repo / ".git").mkdir(parents=True)
        subdir.mkdir(parents=True)

        secret_val = "re_live_exec_masked_secret_value_123456"
        save_entry(Entry(name="resend", fields={"RESEND_API_KEY": secret_val}))

        (repo / ".env.passkey").write_text(
            "RESEND_API_KEY=passkey://resend/RESEND_API_KEY\n",
            encoding="utf-8",
        )

        monkeypatch.setenv("CLAUDECODE", "1")
        monkeypatch.setenv("PASSKEY_OUTPUT", "json")

        # 1. Untrusted manifest + denied Touch ID -> UNTRUSTED_PROJECT on stderr
        with (
            patch("passkey.auth.authenticate", return_value=False) as mock_auth_deny,
            patch.object(
                sys,
                "argv",
                [
                    "passkey",
                    "exec",
                    "--project-dir",
                    str(subdir),
                    "--",
                    sys.executable,
                    "-c",
                    "print('should not run')",
                ],
            ),
            pytest.raises(SystemExit) as exc_deny,
        ):
            main()
        assert exc_deny.value.code == 1
        mock_auth_deny.assert_called_once()
        captured = capsys.readouterr()
        assert captured.out == ""
        err_json = json.loads(captured.err)
        assert err_json["error_code"] == "UNTRUSTED_PROJECT"

        # 2. First approved run prompts Touch ID once, persists HMAC trust, and masks secret
        with (
            patch("passkey.auth.authenticate", return_value=True) as mock_auth_ok,
            patch.object(
                sys,
                "argv",
                [
                    "passkey",
                    "exec",
                    "-q",
                    "--project-dir",
                    str(subdir),
                    "--",
                    sys.executable,
                    "-c",
                    "import os; print('LEAK=' + os.environ['RESEND_API_KEY'])",
                ],
            ),
            pytest.raises(SystemExit) as exc_ok,
        ):
            main()
        assert exc_ok.value.code == 0
        mock_auth_ok.assert_called_once()
        out_first = capsys.readouterr().out
        assert secret_val not in out_first
        assert f"LEAK={CONCEALED_TEXT}" in out_first

        # 3. Subsequent run requires ZERO Touch ID prompts because manifest SHA-256 matches
        with (
            patch("passkey.auth.authenticate", return_value=False) as mock_auth_zero,
            patch.object(
                sys,
                "argv",
                [
                    "passkey",
                    "exec",
                    "-q",
                    "--project-dir",
                    str(subdir),
                    "--",
                    sys.executable,
                    "-c",
                    "import os; assert os.environ['RESEND_API_KEY'].startswith('re_live_'); print('OK')",
                ],
            ),
            pytest.raises(SystemExit) as exc_second,
        ):
            main()
        assert exc_second.value.code == 0
        mock_auth_zero.assert_not_called()
        assert capsys.readouterr().out.strip() == "OK"

    def test_redteam_manifest_modification_sidecar_drop_and_hmac_tampering(
        self, tmp_path, monkeypatch
    ):
        repo = tmp_path / "secure_repo"
        (repo / ".git").mkdir(parents=True)
        save_entry(Entry(name="db", fields={"DATABASE_URL": "postgres://u:secret@db/prod"}))
        save_entry(Entry(name="aws_prod", fields={"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG"}))

        (repo / ".env.passkey").write_text(
            "DATABASE_URL=passkey://db/DATABASE_URL\n",
            encoding="utf-8",
        )

        # Interactive human trusts initial manifest
        monkeypatch.setattr("passkey.project.can_prompt_interactively", lambda: True)
        trust_res = trust_project(repo)
        assert trust_res["trusted"] is True

        # Switch to agent context
        monkeypatch.setattr("passkey.project.can_prompt_interactively", lambda: False)

        # Attack A: Agent drops a brand-new .passkey.toml alongside trusted .env.passkey
        # to silently exfiltrate aws_prod without touching .env.passkey!
        (repo / ".passkey.toml").write_text(
            '[project]\nentries = ["aws_prod"]\n',
            encoding="utf-8",
        )
        status_after_drop = get_project_status(repo)
        assert status_after_drop["trusted"] is False
        assert status_after_drop["trust_status"] == "manifest_modified"

        # Agent calling `passkey project trust` headlessly cannot self-approve without OS auth
        with (
            patch("passkey.auth.authenticate", return_value=False),
            pytest.raises(PasskeyError) as exc_self_trust,
        ):
            trust_project(repo)
        assert exc_self_trust.value.error_code == "UNTRUSTED_PROJECT"

        # Attack B: Agent directly edits trusted_projects.json on disk to forge the new SHA-256
        new_sha = discover_project_manifest(repo)["manifest_sha256"]
        trust_file = get_trusted_projects_path()
        raw_store = json.loads(trust_file.read_text(encoding="utf-8"))
        raw_store["projects"][str(repo.resolve())]["manifest_sha256"] = new_sha
        trust_file.write_text(json.dumps(raw_store), encoding="utf-8")

        with pytest.raises(PasskeyError) as exc_tamper:
            get_project_status(repo)
        assert exc_tamper.value.error_code == "TRUST_STORE_TAMPERED"

    def test_redteam_manifest_path_traversal_and_non_git_boundary(self, tmp_path):
        # 1. Path traversal in [project].env_files rejected
        repo = tmp_path / "bad_repo"
        (repo / ".git").mkdir(parents=True)
        (repo / ".passkey.toml").write_text(
            '[project]\nenv_files = ["../../etc/passwd"]\n',
            encoding="utf-8",
        )
        with pytest.raises(PasskeyError) as exc_trav:
            discover_project_manifest(repo)
        assert exc_trav.value.error_code == "INVALID_MANIFEST"

        # 2. Sensitive .env in [project].env_files rejected
        (repo / ".passkey.toml").write_text(
            '[project]\nenv_files = [".env.production"]\n',
            encoding="utf-8",
        )
        with pytest.raises(PasskeyError) as exc_sens:
            discover_project_manifest(repo)
        assert exc_sens.value.error_code == "INVALID_MANIFEST"

        # 3. Without .git, discover_project_manifest does NOT climb into parent directories
        outer = tmp_path / "outer_unbounded"
        inner = outer / "child_dir"
        inner.mkdir(parents=True)
        (outer / ".env.passkey").write_text("FOO=passkey://db/FOO\n", encoding="utf-8")
        assert discover_project_manifest(inner) is None

    def test_mcp_passkey_project_status_and_exec_dry_run_json(
        self, tmp_path, monkeypatch, capsys
    ):
        repo = tmp_path / "mcp_repo"
        (repo / ".git").mkdir(parents=True)
        secret_val = "sk_live_mcp_project_status_secret_777"
        save_entry(Entry(name="stripe", fields={"STRIPE_SECRET_KEY": secret_val}))
        (repo / ".env.passkey").write_text(
            "STRIPE_SECRET_KEY=passkey://stripe/STRIPE_SECRET_KEY\n",
            encoding="utf-8",
        )

        monkeypatch.setattr("passkey.project.can_prompt_interactively", lambda: True)
        trust_project(repo)

        mcp_res = passkey_project_status(project_dir=str(repo), command=[sys.executable, "-V"])
        assert mcp_res["ok"] is True
        assert mcp_res["manifest_found"] is True
        assert mcp_res["trusted"] is True
        assert mcp_res["ready"] is True
        assert mcp_res["injected_env_vars"] == ["STRIPE_SECRET_KEY"]
        assert mcp_res["command_executable_found"] is True
        assert secret_val not in json.dumps(mcp_res)

        forbidden_res = passkey_project_status(project_dir="/etc")
        assert forbidden_res["ok"] is False
        assert forbidden_res["error_code"] == "FORBIDDEN_PATH"

        # CLI passkey exec --dry-run --json exits 0 when ready & trusted
        with (
            patch.object(
                sys,
                "argv",
                ["passkey", "exec", "--project-dir", str(repo), "--dry-run", "--json"],
            ),
            pytest.raises(SystemExit) as exc_dry,
        ):
            main()
        assert exc_dry.value.code == 0
        dry_json = json.loads(capsys.readouterr().out)
        assert dry_json["ready"] is True
        assert dry_json["trusted"] is True
        assert secret_val not in json.dumps(dry_json)

    def test_seatbelt_keyring_error_antigravity_env_and_hook_install_all(
        self, tmp_path, isolated_data_dir, monkeypatch, capsys
    ):
        from keyring.errors import KeyringError

        from passkey.keychain import KeychainAccessError

        repo = tmp_path / "smoke_hardened"
        (repo / ".git").mkdir(parents=True)
        save_entry(Entry(name="demo", fields={"DEMO_API_KEY": "secret_demo_val"}))
        (repo / ".env.example").write_text("DEMO_API_KEY=\n", encoding="utf-8")

        # 1. ANTIGRAVITY_AGENT=1 prevents silent self-trust even inside a PTY
        monkeypatch.setenv("ANTIGRAVITY_AGENT", "1")
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        res = init_project(project_dir=repo)
        assert res["trusted"] is False

        # Human interactive trust stores HMAC key in keyring
        monkeypatch.delenv("ANTIGRAVITY_AGENT", raising=False)
        trust_project(repo)
        assert not (isolated_data_dir / ".trust_hmac_key").exists()

        # 2. Seatbelt KeyringError (-50) on an existing Keychain-signed store raises
        #    KEYCHAIN_ACCESS_ERROR rather than false TRUST_STORE_TAMPERED
        with (
            patch("passkey.project.keyring.get_password", side_effect=KeyringError("-50")),
            pytest.raises(KeychainAccessError) as exc_kc,
        ):
            get_project_status(repo)
        assert exc_kc.value.error_code == "KEYCHAIN_ACCESS_ERROR"
        assert not (isolated_data_dir / ".trust_hmac_key").exists()

        # 3. passkey hook install --tool all --with-skill installs all hooks + skills
        with patch.object(
            sys,
            "argv",
            [
                "passkey",
                "hook",
                "install",
                "--tool",
                "all",
                "--with-skill",
                "--project-dir",
                str(repo),
            ],
        ):
            main()
        capsys.readouterr()
        assert (repo / ".claude" / "settings.json").is_file()
        assert (repo / ".cursor" / "hooks.json").is_file()
        assert (repo / ".gemini" / "settings.json").is_file()
        assert (repo / ".claude" / "skills" / "passkey" / "SKILL.md").is_file()
        assert (repo / ".cursor" / "rules" / "passkey.mdc").is_file()
        assert (repo / ".gemini" / "skills" / "passkey" / "SKILL.md").is_file()
        assert (repo / "AGENTS.md").is_file()
