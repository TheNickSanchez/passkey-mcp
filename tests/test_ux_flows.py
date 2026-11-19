"""Tests for interactive UX overhaul: prompt_secret, streamlined new/edit, grouped help, and FTUE."""

import io
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from passkey.cli import create_parser, main
from passkey.commands import _entry_edit_loop, cmd_new, cmd_set_field
from passkey.health import cmd_rotate
from passkey.interactive import (
    format_secret_preview,
    parse_field_shorthand,
    prompt_secret,
)
from passkey.keychain import get_entry, list_entries, save_entry
from passkey.mcp_commands import cmd_add, cmd_init
from passkey.mcp_config import ADAPTERS, ToolAdapter
from passkey.models import Entry


def _make_getch(tokens: list[str]):
    it = iter(tokens)
    return lambda: next(it, "\r")


class TestPromptSecretAndPreview:
    """Tests for real-time masked input and safe verification previews."""

    def test_masked_echo_and_live_char_counter(self):
        secret = "sk-live_1234567890abcdefghijklmnopqr"  # 36 chars
        assert len(secret) == 36
        buf = io.StringIO()
        result = prompt_secret(
            "  Value for api_key_test",
            stream=buf,
            _getch=_make_getch([*list(secret), "\r"]),
        )
        rendered = buf.getvalue()
        assert result == secret
        assert "(1 char): •" in rendered
        assert f"Value for api_key_test (36 chars): {'•' * 36}" in rendered
        assert secret not in rendered

    def test_backspace_and_delete_keys(self):
        buf = io.StringIO()
        tokens = ["a", "b", "c", "\x7f", "\x08", "\x1b[3~", "x", "y", "z", "\r"]
        result = prompt_secret("Secret", stream=buf, _getch=_make_getch(tokens))
        assert result == "xyz"
        assert "(3 chars): •••" in buf.getvalue()

    def test_ctrl_u_clears_current_input(self):
        buf = io.StringIO()
        tokens = [*"doublepaste_doublepaste", "\x15", *"clean_val", "\r"]
        result = prompt_secret("Value", stream=buf, _getch=_make_getch(tokens))
        assert result == "clean_val"
        out = buf.getvalue()
        assert "(23 chars)" in out
        assert "(9 chars): •••••••••" in out

    def test_ctrl_r_and_tab_reveal_toggle_and_remask_on_enter(self):
        buf = io.StringIO()
        # Type -> Ctrl+R (reveal) -> Tab (hide) -> Ctrl+R (reveal) -> Enter (must force-remask)
        tokens = [*"sk-verify999", "\x12", "\t", "\x12", "\r"]
        result = prompt_secret("Value for KEY", stream=buf, _getch=_make_getch(tokens))
        assert result == "sk-verify999"
        frames = buf.getvalue().split("\r\x1b[2K")
        # At least one intermediate frame showed [revealed] with the value
        assert any("[revealed]: sk-verify999" in f for f in frames)
        # Final frame before newline must be remasked so scrollback stays clean
        last_frame = frames[-1]
        assert "[revealed]" not in last_frame
        assert "sk-verify999" not in last_frame
        assert "••••••••••••" in last_frame

    def test_ctrl_c_aborts_cleanly_and_remasks(self):
        buf = io.StringIO()
        tokens = [*"topsecret", "\x12", "\x03"]
        with pytest.raises(KeyboardInterrupt):
            prompt_secret("Value", stream=buf, _getch=_make_getch(tokens))
        last_frame = buf.getvalue().split("\r\x1b[2K")[-1]
        assert "topsecret" not in last_frame

    def test_non_tty_fallback_reads_stdin_line(self, monkeypatch):
        monkeypatch.setattr(sys, "stdin", io.StringIO("non_tty_secret_42\n"))
        buf = io.StringIO()
        assert prompt_secret("  Value for TOKEN", stream=buf) == "non_tty_secret_42"

    def test_non_tty_eof_raises_eoferror(self, monkeypatch):
        monkeypatch.setattr(sys, "stdin", io.StringIO(""))
        with pytest.raises(EOFError):
            prompt_secret("Value")

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX pty test")
    def test_real_posix_pty_roundtrip(self, monkeypatch):
        import pty
        import select
        import termios
        import threading

        master_fd, slave_fd = pty.openpty()
        try:
            before_attrs = termios.tcgetattr(slave_fd)
            slave_in = open(slave_fd, encoding="utf-8", closefd=False)  # noqa: SIM115
            slave_out = open(slave_fd, "w", encoding="utf-8", closefd=False)  # noqa: SIM115
            monkeypatch.setattr(sys, "stdin", slave_in)

            done = threading.Event()

            def _feed_and_drain_master():
                # Wait for prompt_secret to enter raw mode and emit its initial prompt
                r, _, _ = select.select([master_fd], [], [], 2.0)
                if r:
                    os.read(master_fd, 1024)
                os.write(master_fd, b"sk-pty-testX\x7f9\r")
                while not done.is_set():
                    r2, _, _ = select.select([master_fd], [], [], 0.02)
                    if r2:
                        try:
                            os.read(master_fd, 1024)
                        except OSError:
                            break

            driver = threading.Thread(target=_feed_and_drain_master, daemon=True)
            driver.start()

            val = prompt_secret("  Value for PTY_KEY", stream=slave_out)
            done.set()
            driver.join(timeout=1.0)

            after_attrs = termios.tcgetattr(slave_fd)
            assert val == "sk-pty-test9"
            flags = termios.ECHO | termios.ICANON | termios.ISIG
            assert (before_attrs[3] & flags) == (after_attrs[3] & flags)
            slave_in.close()
            slave_out.close()
        finally:
            os.close(master_fd)
            os.close(slave_fd)

    def test_format_secret_preview(self):
        assert format_secret_preview("") == "(0 chars, empty)"
        assert format_secret_preview("1234") == "(4 chars, ••••)"
        assert format_secret_preview("1") == "(1 char, •)"
        assert format_secret_preview("abcd5678") == "(8 chars, ab…78)"
        long_key = "sk-" + ("x" * 30) + "9a2"
        assert len(long_key) == 36
        preview = format_secret_preview(long_key)
        assert preview == "(36 chars, sk-…9a2)"
        assert "xxxxx" not in preview

    def test_parse_field_shorthand(self):
        assert parse_field_shorthand("API_KEY=sk-12345") == ("API_KEY", "sk-12345")
        assert parse_field_shorthand("B64_KEY=abc==def=") == ("B64_KEY", "abc==def=")
        assert parse_field_shorthand("export TOKEN=xyz") == ("TOKEN", "xyz")
        assert parse_field_shorthand("PLAIN_FIELD") == ("PLAIN_FIELD", None)


class TestStreamlinedPasskeyNewAndEdit:
    """Tests for frictionless passkey new, KEY=VALUE paste, previews, and save shortcut."""

    def test_new_with_positional_name_skips_template_and_generate_prompts(self, capsys):
        secret_36 = "sk-live_" + ("a" * 25) + "9a2"
        text_answers = iter(["api_key_test", ""])  # field name, then empty Enter -> save!

        def _fake_text(*args, **kwargs):
            m = MagicMock()
            m.ask.side_effect = lambda: next(text_answers)
            return m

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("questionary.text", side_effect=_fake_text),
            patch("questionary.confirm") as mock_confirm,
            patch("passkey.interactive.prompt_secret", return_value=secret_36) as mock_secret,
            patch.object(sys, "argv", ["passkey", "new", "stripe"]),
        ):
            main()

        # Zero confirm prompts ("Start from a template?" and "Generate a secure value?" removed!)
        mock_confirm.assert_not_called()
        mock_secret.assert_called_once()

        entry = get_entry("stripe")
        assert entry is not None
        assert entry.fields == {"api_key_test": secret_36}

        out = capsys.readouterr().out
        assert "(36 chars, sk-…9a2)" in out
        assert secret_36 not in out
        assert "Saved 'stripe' with 1 field(s)" in out

    def test_new_key_equals_value_shorthand_stores_in_one_step(self, capsys):
        text_answers = iter(["API_KEY=sk-12345=extra", "PIN=9876", ""])

        def _fake_text(*args, **kwargs):
            m = MagicMock()
            m.ask.side_effect = lambda: next(text_answers)
            return m

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("questionary.text", side_effect=_fake_text),
            patch("passkey.interactive.prompt_secret") as mock_secret,
        ):
            cmd_new(name="fast_svc")

        # Neither KEY=VALUE field required a second secret prompt
        mock_secret.assert_not_called()
        saved = get_entry("fast_svc")
        assert saved is not None
        assert saved.fields == {"API_KEY": "sk-12345=extra", "PIN": "9876"}

        out = capsys.readouterr().out
        assert "(14 chars, sk-…tra)" in out
        assert "(4 chars, ••••)" in out

    def test_new_explicit_template_flag(self, capsys):
        mock_text = MagicMock()
        mock_text.ask.return_value = ""
        mock_confirm = MagicMock()
        mock_confirm.ask.return_value = False
        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("questionary.text", return_value=mock_text),
            patch("questionary.confirm", return_value=mock_confirm),
            patch("passkey.interactive.prompt_secret", return_value="ghp_1234567890abcdef"),
            patch.object(sys, "argv", ["passkey", "new", "gh_prod", "--template", "github"]),
        ):
            main()

        entry = get_entry("gh_prod")
        assert entry is not None
        assert entry.source == "template:github"
        assert "GITHUB_TOKEN" in entry.fields

    def test_entry_edit_loop_generate_and_empty_add_saves(self, capsys):
        select_answers = iter(["generate", "add"])
        text_answers = iter(["GENERATED_SECRET", ""])  # generate field, then empty Enter in add -> save!

        def _fake_select(*args, **kwargs):
            m = MagicMock()
            m.ask.side_effect = lambda: next(select_answers)
            return m

        def _fake_text(*args, **kwargs):
            m = MagicMock()
            m.ask.side_effect = lambda: next(text_answers)
            return m

        with (
            patch("questionary.select", side_effect=_fake_select),
            patch("questionary.text", side_effect=_fake_text),
        ):
            res = _entry_edit_loop("demo", {"SHORT": "1234"}, {})

        assert res is not None
        final_name, fields, _ = res
        assert final_name == "demo"
        assert "GENERATED_SECRET" in fields
        assert len(fields["GENERATED_SECRET"]) == 32
        out = capsys.readouterr().out
        assert "(4 chars, ••••)" in out

    def test_set_field_rotate_and_add_use_prompt_secret(self, tmp_path):
        entry = Entry(
            name="stripe",
            fields={"API_KEY": "old_value"},
            config={"STRIPE_ENV": "live"},
            created="2025-01-01T00:00:00",
            source="manual",
        )
        save_entry(entry)

        # 1. set-field
        with patch("passkey.interactive.prompt_secret", return_value="sk_new_1234567890") as m_sec:
            cmd_set_field(get_entry("stripe"), "API_KEY", None)
        m_sec.assert_called_once()
        updated = get_entry("stripe")
        assert updated.fields["API_KEY"] == "sk_new_1234567890"
        assert updated.config == {"STRIPE_ENV": "live"}
        assert updated.created == "2025-01-01T00:00:00"

        # 2. rotate
        with patch("passkey.interactive.prompt_secret", return_value="sk_rotated_99999999") as m_rot:
            cmd_rotate("stripe", "API_KEY")
        m_rot.assert_called_once()
        rotated = get_entry("stripe")
        assert rotated.fields["API_KEY"] == "sk_rotated_99999999"
        assert rotated.last_rotated is not None
        assert rotated.config == {"STRIPE_ENV": "live"}

        # 3. add (MCP credentials)
        claude_cfg = tmp_path / "claude.json"
        claude_cfg.write_text(json.dumps({"mcpServers": {}}))
        fake_adapter = ToolAdapter(
            name="claude",
            display_name="Claude Code",
            root_key="mcpServers",
            global_paths={sys.platform: claude_cfg},
        )
        with (
            patch.dict(ADAPTERS, {"claude": fake_adapter}, clear=False),
            patch("passkey.mcp_commands.prompt_secret", return_value="xoxb-slack-token-1234") as m_add,
        ):
            cmd_add("slack_mcp", tool="claude", fields=["SLACK_BOT_TOKEN"])
        m_add.assert_called_once()
        assert get_entry("slack_mcp").fields == {"SLACK_BOT_TOKEN": "xoxb-slack-token-1234"}


class TestHelpGroupingAndBackwardsCompat:
    """Tests for gh-style grouped --help, hidden aliases, and passkey mcp/entry subcommands."""

    def test_top_level_help_layout_and_hidden_plumbing(self):
        parser = create_parser()
        help_text = parser.format_help()

        assert "usage: passkey <command> [options]" in help_text
        for header in (
            "Core Secret Management:",
            "Run & Inject:",
            "MCP & AI Guardrails:",
            "Portability & Config:",
        ):
            assert header in help_text

        # Primary commands visible
        for primary in (
            "new",
            "get",
            "list",
            "edit",
            "delete",
            "info",
            "run",
            "inject",
            "mount",
            "plugin",
            "browser-fill",
            "init",
            "status",
            "doctor",
            "hook",
            "audit",
            "policy",
            "lease",
            "export",
            "import",
            "share",
            "receive",
            "config",
            "completion",
        ):
            assert f"  {primary}" in help_text

        # Plumbing and secondary flat aliases hidden from primary help wall
        for hidden in (
            "mcp-serve",
            "  servers ",
            "  unwrap ",
            "  set-field ",
            "  clone ",
            "  rotate ",
        ):
            assert hidden not in help_text

        # Examples trimmed to 6-8 lines
        examples_block = help_text.split("Examples:\n", 1)[1].split("\n\n", 1)[0]
        example_lines = [ln for ln in examples_block.splitlines() if ln.strip()]
        assert 6 <= len(example_lines) <= 8

    def test_backwards_compatible_top_level_aliases_and_noun_verb_groups(self, capsys):
        save_entry(Entry(name="alpha", fields={"API_KEY": "val_alpha_1234"}))

        # Top-level check alias + passkey entry check
        for argv in (
            ["passkey", "check", "alpha", "API_KEY"],
            ["passkey", "entry", "check", "alpha", "API_KEY"],
        ):
            with patch.object(sys, "argv", argv), pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0
        capsys.readouterr()

        # Top-level generate + passkey entry generate
        for argv in (
            ["passkey", "generate", "--length", "20", "--no-copy"],
            ["passkey", "entry", "generate", "--length", "20", "--no-copy"],
        ):
            with patch.object(sys, "argv", argv):
                main()
            generated = capsys.readouterr().out.strip()
            assert len(generated) == 20

        # Top-level clone + passkey entry clone
        with (
            patch("passkey.interactive.is_interactive", return_value=False),
            patch.object(sys, "argv", ["passkey", "clone", "alpha", "alpha_c1"]),
        ):
            main()
        assert get_entry("alpha_c1") is not None

        with (
            patch("passkey.interactive.is_interactive", return_value=False),
            patch.object(sys, "argv", ["passkey", "entry", "clone", "alpha", "alpha_c2"]),
        ):
            main()
        assert get_entry("alpha_c2") is not None
        capsys.readouterr()

        # Top-level status/servers vs passkey mcp status/servers/doctor/unwrap
        for argv in (
            ["passkey", "status"],
            ["passkey", "mcp", "status"],
            ["passkey", "servers"],
            ["passkey", "mcp", "servers"],
            ["passkey", "unwrap", "--dry-run"],
            ["passkey", "mcp", "unwrap", "--dry-run"],
            ["passkey", "mcp", "doctor"],
        ):
            with patch.object(sys, "argv", argv):
                main()
            capsys.readouterr()

    def test_help_and_version_subcommands_and_short_flag(self, capsys):
        # 1. `passkey help` (no --) prints categorized top-level help
        with patch.object(sys, "argv", ["passkey", "help"]):
            main()
        help_out = capsys.readouterr().out
        assert "Core Secret Management:" in help_out

        # 2. `passkey help new` and `passkey help mcp init` print subcommand help
        with patch.object(sys, "argv", ["passkey", "help", "new"]), pytest.raises(SystemExit) as e1:
            main()
        assert e1.value.code == 0
        assert "--template" in capsys.readouterr().out

        with (
            patch.object(sys, "argv", ["passkey", "help", "mcp", "init"]),
            pytest.raises(SystemExit) as e2,
        ):
            main()
        assert e2.value.code == 0
        assert "--dry-run" in capsys.readouterr().out

        # 3. `passkey version` and `passkey -V` both print version
        with patch.object(sys, "argv", ["passkey", "version"]):
            main()
        ver_sub = capsys.readouterr().out.strip()
        assert ver_sub.startswith("passkey ")

        with patch.object(sys, "argv", ["passkey", "-V"]), pytest.raises(SystemExit) as e3:
            main()
        assert e3.value.code == 0
        assert capsys.readouterr().out.strip() == ver_sub

    def test_help_and_version_are_reserved_entry_names(self, capsys):
        from passkey.models import RESERVED_NAMES, is_valid_name

        for reserved in ("help", "version"):
            assert reserved in RESERVED_NAMES
            assert is_valid_name(reserved) is False
            with pytest.raises(ValueError, match="reserved name"):
                Entry(name=reserved, fields={"K": "V"})

            with (
                patch.object(sys, "argv", ["passkey", "new", reserved]),
                pytest.raises(SystemExit) as exc,
            ):
                main()
            assert exc.value.code == 1
            assert "reserved name" in capsys.readouterr().err


class TestBarePasskeyFTUEAndInitPreview:
    """Tests for bare passkey States A, B, C and clearer passkey init preview."""

    def test_ftue_state_a_exposed_mcp_servers_prompts_migration(self, tmp_path, capsys):
        assert list_entries() == []
        cfg = tmp_path / "claude.json"
        cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "github": {
                            "command": "npx",
                            "args": ["-y", "@modelcontextprotocol/server-github"],
                            "env": {
                                "GITHUB_TOKEN": "ghp_exposed_token_1234567890",
                                "LOG_LEVEL": "info",
                            },
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

        mock_q = MagicMock()
        mock_q.ask.return_value = "init"

        with (
            patch.dict(ADAPTERS, {"claude": fake_claude}, clear=True),
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("questionary.select", return_value=mock_q) as select_spy,
            patch("builtins.input", return_value="y"),
            patch.object(sys, "argv", ["passkey"]),
        ):
            main()

        out = capsys.readouterr().out
        # State A welcome summarized exposed server
        assert "Claude Code" in out
        assert "github" in out
        assert "GITHUB_TOKEN" in out
        # Prompted with clean arrow-key menu label (no [Y/n] suffix)
        assert select_spy.call_args[0][0] == "How would you like to get started?"
        assert "[Y/n]" not in select_spy.call_args[0][0]
        # Secret migrated to keychain and masked in preview
        migrated = get_entry("github")
        assert migrated is not None
        assert migrated.fields == {"GITHUB_TOKEN": "ghp_exposed_token_1234567890"}
        assert "ghp_exposed_token_1234567890" not in out

    def test_ftue_state_b_clean_machine_offers_new_or_examples(self, capsys):
        assert list_entries() == []
        mock_q = MagicMock()
        mock_q.ask.return_value = "examples"

        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("questionary.select", return_value=mock_q) as select_spy,
            patch.object(sys, "argv", ["passkey"]),
        ):
            main()

        out = capsys.readouterr().out
        choice_titles = [c.title for c in select_spy.call_args.kwargs["choices"]]
        assert any("Create your first secret" in t for t in choice_titles)
        assert any("Show quickstart examples" in t for t in choice_titles)
        assert "Quickstart Examples:" in out

    def test_ftue_state_c_existing_entries_jumps_to_fuzzy_browser(self):
        entry = Entry(name="stripe", fields={"STRIPE_SECRET_KEY": "sk_test_123"})
        save_entry(entry)

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("passkey.interactive.select_entry", return_value="stripe") as mock_select,
            patch("passkey.commands.cmd_get_interactive") as mock_get_ui,
            patch.object(sys, "argv", ["passkey"]),
        ):
            main()

        mock_select.assert_called_once()
        mock_get_ui.assert_called_once()
        assert mock_get_ui.call_args[0][0].name == "stripe"

    def test_state_c_single_field_autocopies_immediately(self, capsys):
        entry = Entry(name="github", fields={"GITHUB_TOKEN": "ghp_single_secret_123456"})
        save_entry(entry)

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("passkey.interactive.select_entry", return_value="github"),
            patch("passkey.commands.copy_with_autoclear") as mock_copy,
            patch("questionary.select") as mock_field_select,
            patch.object(sys, "argv", ["passkey"]),
        ):
            main()

        # Single-field entry copies immediately without a second picker prompt
        mock_field_select.assert_not_called()
        mock_copy.assert_called_once_with("ghp_single_secret_123456", timeout_seconds=30)
        out = capsys.readouterr().out
        assert "Copied 'GITHUB_TOKEN' from 'github' to clipboard (auto-clears in 30s)" in out

    def test_get_interactive_multi_field_uses_arrow_key_picker(self, capsys):
        from passkey.commands import cmd_get_interactive

        entry = Entry(
            name="stripe",
            fields={
                "STRIPE_SECRET_KEY": "sk_live_1234567890abcdef9a2",
                "WEBHOOK_PIN": "4821",
            },
        )
        mock_q = MagicMock()
        mock_q.ask.return_value = "STRIPE_SECRET_KEY"

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("questionary.select", return_value=mock_q) as select_spy,
            patch("passkey.commands.copy_with_autoclear") as mock_copy,
        ):
            cmd_get_interactive(entry)

        select_spy.assert_called_once()
        assert select_spy.call_args[0][0] == "Select field from 'stripe'"
        choice_titles = [
            c.title
            for c in select_spy.call_args.kwargs["choices"]
            if hasattr(c, "title") and isinstance(c.title, str)
        ]
        assert any("STRIPE_SECRET_KEY" in t and "sk_…9a2" in t for t in choice_titles)
        assert any("WEBHOOK_PIN" in t and "••••" in t for t in choice_titles)
        assert any("Copy all fields" in t for t in choice_titles)
        mock_copy.assert_called_once_with("sk_live_1234567890abcdef9a2", timeout_seconds=30)
        assert "Copied 'STRIPE_SECRET_KEY' from 'stripe' to clipboard" in capsys.readouterr().out

    def test_init_preview_shows_masked_secrets_non_secrets_backup_and_unwrap(
        self, tmp_path, isolated_data_dir, capsys
    ):
        secret_val = "sk_live_abcdefgh1234567890xyz"
        cfg = tmp_path / "claude.json"
        cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "stripe": {
                            "command": "npx",
                            "args": ["-y", "@stripe/mcp"],
                            "env": {
                                "STRIPE_SECRET_KEY": secret_val,
                                "NODE_ENV": "production",
                            },
                        }
                    }
                }
            )
        )

        cmd_init(tool="claude", config_path=str(cfg), dry_run=True)
        out = capsys.readouterr().out

        # 1. Masked preview shown, plaintext secret NEVER leaked
        assert secret_val not in out
        assert "(29 chars, sk_…xyz)" in out
        # 2. Non-secret env var shown as staying inline
        assert "NODE_ENV = production" in out
        # 3. 0o600 backup path under <data_dir>/backups/
        assert str(isolated_data_dir / "backups") in out
        assert "0o600" in out
        # 4. Exact passkey unwrap rollback command
        assert f"passkey unwrap --tool claude --config {cfg}" in out
