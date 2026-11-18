"""Tests for Wave 3 zero-config CLI wrapper plugins (passkey plugin)."""

import sys

import pytest

from passkey.keychain import PasskeyError, save_entry
from passkey.masking import CONCEALED_TEXT
from passkey.models import Entry
from passkey.plugins import (
    PLUGIN_SPECS,
    init_plugin,
    list_plugins,
    resolve_plugin_entry,
    run_plugin,
)
from passkey.templates import list_templates


class TestCLIWrapperPlugins:
    """Tests for built-in AI/cloud plugin specs, scope precedence, and masked execution."""

    def test_all_required_plugin_specs_and_templates_registered(self):
        expected_clis = {
            "claude",
            "codex",
            "openai",
            "gemini",
            "cursor-agent",
            "gh",
            "aws",
            "wrangler",
            "vercel",
            "stripe",
        }
        assert expected_clis.issubset(set(PLUGIN_SPECS.keys()))

        template_names = {t["name"] for t in list_templates()}
        for tpl in ("claude", "codex", "gemini", "cursor-agent", "wrangler"):
            assert tpl in template_names

    def test_scope_precedence_session_over_dir_over_global(
        self, tmp_path, isolated_data_dir, monkeypatch
    ):
        save_entry(Entry(name="claude_global", fields={"ANTHROPIC_API_KEY": "sk-ant-global-12345"}))
        save_entry(Entry(name="claude_dir", fields={"ANTHROPIC_API_KEY": "sk-ant-dir-12345678"}))
        save_entry(Entry(name="claude_sess", fields={"ANTHROPIC_API_KEY": "sk-ant-sess-1234567"}))

        # 1. Global binding
        g_info = init_plugin("claude", entry_name="claude_global", scope="global")
        assert g_info["entry"] == "claude_global"
        sh_text = (isolated_data_dir / "plugins.sh").read_text()
        assert "claude() { command passkey plugin run claude -- \"$@\"; }" in sh_text

        sub_dir = tmp_path / "workspace" / "sub"
        sub_dir.mkdir(parents=True)
        entry_g, src_g = resolve_plugin_entry("claude", cwd=sub_dir)
        assert entry_g == "claude_global"
        assert src_g == "global"

        # 2. Directory .passkey.toml binding overrides global (including from child subdir)
        d_info = init_plugin(
            "claude",
            entry_name="claude_dir",
            scope="dir",
            project_dir=tmp_path / "workspace",
        )
        assert (tmp_path / "workspace" / ".passkey.toml").exists()
        assert "sk-ant" not in (tmp_path / "workspace" / ".passkey.toml").read_text()
        assert d_info["scope"] == "dir"

        entry_d, src_d = resolve_plugin_entry("claude", cwd=sub_dir)
        assert entry_d == "claude_dir"
        assert src_d.startswith("dir")

        # 3. Session env var overrides both dir and global
        s_info = init_plugin("claude", entry_name="claude_sess", scope="session")
        assert "PASSKEY_PLUGIN_CLAUDE='claude_sess'" in s_info["snippet"]
        monkeypatch.setenv("PASSKEY_PLUGIN_CLAUDE", "claude_sess")
        entry_s, src_s = resolve_plugin_entry("claude", cwd=sub_dir)
        assert entry_s == "claude_sess"
        assert src_s.startswith("session")

        listed = {item["cli"]: item for item in list_plugins(cwd=sub_dir)}
        assert listed["claude"]["entry"] == "claude_sess"

    def test_run_plugin_maps_alias_and_masks_secret_output(self, tmp_path, capsys):
        # Store GITHUB_TOKEN (from github template) and verify `gh` plugin maps it to GH_TOKEN
        secret_pat = "ghp_plugin_aliased_secret_token_999"
        save_entry(Entry(name="github", fields={"GITHUB_TOKEN": secret_pat}))

        fake_gh = tmp_path / "gh"
        fake_gh.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "sys.stdout.write('GH_TOKEN=' + os.environ['GH_TOKEN'] + ' args=' + ','.join(sys.argv[1:]) + '\\n')\n"
        )
        fake_gh.chmod(0o755)

        rc = run_plugin(
            "gh",
            ["pr", "status"],
            entry_name="github",
            executable_override=str(fake_gh),
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert secret_pat not in out
        assert f"GH_TOKEN={CONCEALED_TEXT} args=pr,status" in out

    def test_run_plugin_fails_when_required_field_missing(self, tmp_path):
        save_entry(Entry(name="broken_aws", fields={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}))
        with pytest.raises(PasskeyError, match="AWS_SECRET_ACCESS_KEY"):
            run_plugin("aws", ["sts", "get-caller-identity"], entry_name="broken_aws")
