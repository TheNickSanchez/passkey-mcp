"""Tests for Tier P1 Agent-Experience (AX) upgrades.

Covers:
- MCP discovery & preflight: passkey_entry_info, passkey_preflight_run, passkey_validate_references
- MCP metadata: FastMCP instructions, ToolAnnotations (readOnlyHint / destructiveHint), and 3 @mcp.prompt() workflows
- Remaining --json CLI commands: audit, audit --summary, audit --verify, lease list, plugin list, policy, config, skill install
- Agent skill & rules installer: passkey skill install (--tool claude|cursor|gemini|agents|all) and hook install --with-skill
- Hardened hooks & git-exposure guard on cmd_inject
"""

import asyncio
import json
import subprocess
import sys
from unittest.mock import patch

import pytest

from passkey.audit import get_log_path, get_recent_logs
from passkey.cli import main
from passkey.hooks import evaluate_hook_payload
from passkey.keychain import save_entry
from passkey.leases import grant_lease, peek_lease
from passkey.mcp_server import (
    MCP_INSTRUCTIONS,
    debug_missing_credential,
    mcp,
    migrate_exposed_mcp_configs,
    passkey_entry_info,
    passkey_fields,
    passkey_preflight_run,
    passkey_validate_references,
    setup_project_secrets,
)
from passkey.models import Entry
from passkey.skills import AGENTS_MARKER_END, AGENTS_MARKER_START


class TestMcpDiscoveryPreflightAndPrompts:
    """Verify richer MCP discovery tools, annotations, instructions, and prompts."""

    def test_passkey_entry_info_missing_and_existing_preserves_leases_and_secrets(self):
        missing = passkey_entry_info("nonexistent_entry")
        assert missing["exists"] is False
        assert missing["name"] == "nonexistent_entry"
        assert "passkey new nonexistent_entry" in missing["remediation"]

        secret_val = "sk_live_MCP_NEVER_LEAK_777"
        config_val = "https://secret-internal-host.example"
        save_entry(
            Entry(
                name="stripe_mcp",
                fields={"STRIPE_SECRET_KEY": secret_val, "WEBHOOK_SECRET": "whsec_888"},
                config={"STRIPE_API_BASE": config_val},
                policy="prompt",
                source="manual",
            )
        )

        # Clear creation audit entry check baseline: count existing 'read' ops
        reads_before = [r for r in get_recent_logs() if r.get("operation") == "read"]

        info_no_lease = passkey_entry_info("stripe_mcp")
        assert info_no_lease["exists"] is True
        assert info_no_lease["policy"] == "prompt"
        assert info_no_lease["has_active_lease"] is False
        assert info_no_lease["will_prompt_biometric"] is True
        assert info_no_lease["fields"] == ["STRIPE_SECRET_KEY", "WEBHOOK_SECRET"]
        assert info_no_lease["config_keys"] == ["STRIPE_API_BASE"]
        assert secret_val not in json.dumps(info_no_lease)
        assert config_val not in json.dumps(info_no_lease)

        # Grant single-use lease and verify neither passkey_entry_info nor passkey_fields consumes it or logs a read
        grant_lease("stripe_mcp", ttl="15m", max_uses=1, require_biometric=False)
        info_leased = passkey_entry_info("stripe_mcp")
        assert info_leased["has_active_lease"] is True
        assert info_leased["lease_remaining_uses"] == 1
        assert info_leased["will_prompt_biometric"] is False

        field_names = passkey_fields("stripe_mcp")
        assert sorted(field_names) == ["STRIPE_SECRET_KEY", "WEBHOOK_SECRET"]

        reads_after = [r for r in get_recent_logs() if r.get("operation") == "read"]
        assert len(reads_after) == len(reads_before)

        still_leased = peek_lease("stripe_mcp")
        assert still_leased is not None
        assert still_leased["remaining_uses"] == 1

    def test_passkey_preflight_run_and_validate_references(self, tmp_path):
        secret_val = "ghp_SUPER_SECRET_TOKEN_12345"
        save_entry(
            Entry(
                name="github",
                fields={"GITHUB_TOKEN": secret_val},
                policy="prompt",
            )
        )

        env_file = tmp_path / ".env.passkey"
        env_file.write_text("GH_TOKEN=passkey://github/GITHUB_TOKEN\n", encoding="utf-8")

        val_res = passkey_validate_references(str(env_file))
        assert val_res["valid"] is True
        assert val_res["checked"] == 1
        assert val_res["prompt_entries_without_lease"] == ["github"]
        assert val_res["will_prompt_biometric"] is True
        assert secret_val not in json.dumps(val_res)

        preflight_res = passkey_preflight_run(
            entries=["github"],
            env_files=[str(env_file)],
            command=[sys.executable, "-c", "pass"],
        )
        assert preflight_res["ready"] is True
        assert preflight_res["injected_env_vars"] == ["GH_TOKEN", "GITHUB_TOKEN"]
        assert preflight_res["prompt_entries_without_lease"] == ["github"]
        assert preflight_res["will_prompt_biometric"] is True
        assert preflight_res["command_executable_found"] is True
        assert secret_val not in json.dumps(preflight_res)

        # Forbidden system path must be rejected cleanly
        forbidden = passkey_preflight_run(entries=[], env_files=["/etc/passwd"])
        assert forbidden["ready"] is False
        assert "/etc/passwd" in forbidden["env_files_missing"]
        assert "Access to system path denied." in forbidden["remediation"]

    def test_fastmcp_instructions_tool_annotations_and_prompts(self):
        assert mcp.instructions == MCP_INSTRUCTIONS
        assert "Never run interactive commands" in mcp.instructions

        tools = asyncio.run(mcp.list_tools())
        by_name = {t.name: t for t in tools}
        assert len(by_name) >= 13

        read_only_tools = {
            "passkey_list",
            "passkey_fields",
            "passkey_entry_info",
            "passkey_find",
            "passkey_preflight_run",
            "passkey_project_status",
            "passkey_status",
            "passkey_doctor",
            "passkey_validate_references",
            "passkey_audit_recent",
        }
        mutating_tools = {
            "passkey_request_secret",
            "passkey_wrap_server",
            "passkey_cdp_autofill",
        }

        for name in read_only_tools:
            assert by_name[name].annotations is not None
            assert by_name[name].annotations.readOnlyHint is True
            assert by_name[name].annotations.destructiveHint is False

        for name in mutating_tools:
            assert by_name[name].annotations is not None
            assert by_name[name].annotations.readOnlyHint is False

        prompts = asyncio.run(mcp.list_prompts())
        prompt_names = {p.name for p in prompts}
        assert prompt_names == {
            "setup-project-secrets",
            "debug-missing-credential",
            "migrate-exposed-mcp-configs",
        }

        rendered_setup = setup_project_secrets(project_dir="my-app; rm -rf /")
        assert "rm -rf" in rendered_setup  # alphanumeric kept, shell metacharacters stripped
        assert ";" not in rendered_setup
        assert "/" not in rendered_setup.splitlines()[0]
        assert "passkey_preflight_run" in rendered_setup

        rendered_debug = debug_missing_credential("stripe", command="pytest -q")
        assert "passkey_entry_info(entry_name='stripe')" in rendered_debug
        assert "passkey lease grant stripe --ttl 15m" in rendered_debug

        rendered_migrate = migrate_exposed_mcp_configs()
        assert "passkey_status()" in rendered_migrate
        assert "passkey init --dry-run" in rendered_migrate


class TestRemainingCliJsonOutputs:
    """Verify --json on audit, lease list, plugin list, policy, and config."""

    def test_audit_json_modes_and_tamper_detection(self, capsys):
        save_entry(Entry(name="audit_target", fields={"KEY": "secret_audit_val"}))

        # 1. passkey audit --json strips hmac and prev_hmac
        with patch.object(sys, "argv", ["passkey", "audit", "--limit", "5", "--json"]):
            main()
        logs = json.loads(capsys.readouterr().out)
        assert len(logs) >= 1
        assert "hmac" not in logs[0]
        assert "prev_hmac" not in logs[0]
        assert "secret_audit_val" not in json.dumps(logs)

        # 2. passkey audit --summary --json
        with patch.object(sys, "argv", ["passkey", "audit", "--summary", "--json"]):
            main()
        summary = json.loads(capsys.readouterr().out)
        assert summary["window_days"] == 30
        assert summary["total_operations"] >= 1
        assert "create" in summary["operations"]

        # 3. passkey audit --verify --json (valid -> exit 0)
        with patch.object(sys, "argv", ["passkey", "audit", "--verify", "--json"]):
            main()
        ver_ok = json.loads(capsys.readouterr().out)
        assert ver_ok["valid"] is True
        assert ver_ok["checked"] >= 1

        # 4. Tamper with audit.log -> passkey audit --verify --json exits 1 with valid=False
        log_path = get_log_path()
        lines = log_path.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["entry"] = "forged_entry"
        lines[0] = json.dumps(rec)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with (
            patch.object(sys, "argv", ["passkey", "audit", "--verify", "--json"]),
            pytest.raises(SystemExit) as exc_bad,
        ):
            main()
        assert exc_bad.value.code == 1
        ver_bad = json.loads(capsys.readouterr().out)
        assert ver_bad["valid"] is False

    def test_lease_list_plugin_list_policy_and_config_json(self, capsys):
        save_entry(Entry(name="github", fields={"GH_TOKEN": "ghp_secret_999"}))

        # lease list --json (empty -> [], active -> list)
        with patch.object(sys, "argv", ["passkey", "lease", "list", "--json"]):
            main()
        assert json.loads(capsys.readouterr().out) == []

        grant_lease("github", ttl="10m", max_uses=3, require_biometric=False)
        with patch.object(sys, "argv", ["passkey", "lease", "list", "--json"]):
            main()
        leases = json.loads(capsys.readouterr().out)
        assert len(leases) == 1
        assert leases[0]["entry"] == "github"
        assert leases[0]["remaining_uses"] == 3

        # plugin list --json includes entry_exists
        with patch.object(sys, "argv", ["passkey", "plugin", "list", "--json"]):
            main()
        plugins = json.loads(capsys.readouterr().out)
        by_cli = {p["cli"]: p for p in plugins}
        assert by_cli["gh"]["entry"] == "github"
        assert by_cli["gh"]["entry_exists"] is True
        assert by_cli["stripe"]["entry_exists"] is False

        # policy --json (read and update)
        with patch.object(sys, "argv", ["passkey", "policy", "github", "--json"]):
            main()
        pol_read = json.loads(capsys.readouterr().out)
        assert pol_read == {
            "entry": "github",
            "policy": "allow",
            "has_active_lease": True,
            "updated": False,
        }

        with patch.object(sys, "argv", ["passkey", "policy", "github", "prompt", "--json"]):
            main()
        pol_set = json.loads(capsys.readouterr().out)
        assert pol_set["policy"] == "prompt"
        assert pol_set["updated"] is True

        # config --json (all, single key, update)
        with patch.object(sys, "argv", ["passkey", "config", "--json"]):
            main()
        cfg_all = json.loads(capsys.readouterr().out)
        assert cfg_all["mcp_browser_broker"] is False

        with patch.object(sys, "argv", ["passkey", "config", "mcp-browser-broker", "on", "--json"]):
            main()
        cfg_upd = json.loads(capsys.readouterr().out)
        assert cfg_upd == {"key": "mcp_browser_broker", "value": True, "updated": True}

        with patch.object(sys, "argv", ["passkey", "config", "mcp-browser-broker", "--json"]):
            main()
        cfg_one = json.loads(capsys.readouterr().out)
        assert cfg_one == {"key": "mcp_browser_broker", "value": True}


class TestSkillInstallerHooksAndInjectGitGuard:
    """Verify passkey skill install, hook hardening, and cmd_inject git-exposure guard."""

    def test_skill_install_all_and_idempotent_agents_md(self, tmp_path, capsys):
        agents_md = tmp_path / "AGENTS.md"
        agents_md.write_text(
            "# Existing Repo Rules\n\nKeep existing project architecture intact.\n",
            encoding="utf-8",
        )

        with patch.object(
            sys,
            "argv",
            [
                "passkey",
                "skill",
                "install",
                "--tool",
                "all",
                "--project-dir",
                str(tmp_path),
                "--json",
            ],
        ):
            main()

        res = json.loads(capsys.readouterr().out)
        assert len(res["installed"]) == 4
        assert (tmp_path / ".claude" / "skills" / "passkey" / "SKILL.md").is_file()
        assert (tmp_path / ".cursor" / "rules" / "passkey.mdc").is_file()
        assert (tmp_path / ".gemini" / "skills" / "passkey" / "SKILL.md").is_file()

        first_agents = agents_md.read_text(encoding="utf-8")
        assert "Keep existing project architecture intact." in first_agents
        assert first_agents.count(AGENTS_MARKER_START) == 1
        assert first_agents.count(AGENTS_MARKER_END) == 1

        # Re-running must update in-place without duplicating markers or losing surrounding text
        agents_md.write_text(first_agents + "\n## Footer Section\nDo not delete.\n", encoding="utf-8")
        with patch.object(
            sys,
            "argv",
            ["passkey", "skill", "install", "--tool", "agents", "--project-dir", str(tmp_path)],
        ):
            main()
        capsys.readouterr()

        second_agents = agents_md.read_text(encoding="utf-8")
        assert second_agents.count(AGENTS_MARKER_START) == 1
        assert second_agents.count(AGENTS_MARKER_END) == 1
        assert "Keep existing project architecture intact." in second_agents
        assert "## Footer Section\nDo not delete." in second_agents

    def test_hook_install_with_skill_flag(self, tmp_path, capsys):
        with patch.object(
            sys,
            "argv",
            [
                "passkey",
                "hook",
                "install",
                "--tool",
                "claude",
                "--with-skill",
                "--project-dir",
                str(tmp_path),
            ],
        ):
            main()
        out = capsys.readouterr().out
        assert "Installed passkey guard hook" in out
        assert "Installed passkey agent skill" in out
        assert (tmp_path / ".claude" / "settings.json").is_file()
        assert (tmp_path / ".claude" / "skills" / "passkey" / "SKILL.md").is_file()

    @pytest.mark.parametrize(
        "cmd",
        [
            "passkey get stripe",
            "passkey --no-input get stripe",
            "passkey entry get stripe",
            "passkey --no-input export dump.json",
            "passkey generate --no-copy",
            "passkey entry generate --no-copy",
            "passkey inject -i .env.template --stdout",
            "passkey inject -i .env.template -o -",
            "passkey inject -i .env.template --out-file=-",
            "passkey policy stripe allow",
            "passkey --no-input policy stripe session --json",
            "passkey entry policy stripe prompt",
            "passkey policy --all allow --yes",
            "passkey policy --all session --exclude-mcp",
            "passkey config default-policy allow",
            "passkey config default_policy session --json",
        ],
    )
    def test_hardened_hook_blocks_secret_exfiltrating_passkey_subcommands(self, cmd):
        allowed, reason = evaluate_hook_payload({"tool_input": {"command": cmd}})
        assert allowed is False, f"Expected hook to block: {cmd}"
        assert "Blocked by passkey hook" in reason

    @pytest.mark.parametrize(
        "cmd",
        [
            "passkey policy stripe",
            "passkey policy stripe --json",
            "passkey --no-input policy stripe --json",
            "passkey entry policy stripe --json",
            "passkey config",
            "passkey config --json",
            "passkey config default-policy",
            "passkey config default-policy --json",
            "passkey config default_policy --json",
        ],
    )
    def test_hook_allows_readonly_policy_and_default_policy_inspection(self, cmd):
        allowed, reason = evaluate_hook_payload({"tool_input": {"command": cmd}})
        assert allowed is True, f"Expected hook to allow read-only command '{cmd}', got: {reason}"

    def test_inject_blocks_unignored_git_output_unless_gitignored_or_forced(self, tmp_path, capsys):
        subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
        save_entry(Entry(name="db", fields={"DATABASE_URL": "postgres://secret:pw@localhost/db"}))

        tpl = tmp_path / ".env.template"
        tpl.write_text("DATABASE_URL={{ passkey://db/DATABASE_URL }}\n", encoding="utf-8")
        out_env = tmp_path / ".env"

        # 1. Blocked when .env is not in .gitignore
        with (
            patch.object(
                sys, "argv", ["passkey", "inject", "-i", str(tpl), "-o", str(out_env)]
            ),
            pytest.raises(SystemExit) as exc_git,
        ):
            main()
        assert exc_git.value.code == 1
        err = capsys.readouterr().err
        assert "NOT gitignored" in err
        assert not out_env.exists()

        # 2. Allowed once .env is added to .gitignore
        (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
        with patch.object(
            sys, "argv", ["passkey", "inject", "-i", str(tpl), "-o", str(out_env)]
        ):
            main()
        capsys.readouterr()
        assert out_env.is_file()
        assert "postgres://secret:pw@localhost/db" in out_env.read_text(encoding="utf-8")

        # 3. Also allowed on unignored path when --force-git-exposed is explicitly passed
        exposed_out = tmp_path / "unignored.cfg"
        with patch.object(
            sys,
            "argv",
            [
                "passkey",
                "inject",
                "-i",
                str(tpl),
                "-o",
                str(exposed_out),
                "--force-git-exposed",
            ],
        ):
            main()
        capsys.readouterr()
        assert exposed_out.is_file()
