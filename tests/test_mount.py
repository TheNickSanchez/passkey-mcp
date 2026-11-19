"""Tests for Wave 2 ephemeral UNIX FIFO mounting (passkey mount) and agent hooks."""

import json
import stat
import subprocess
import sys
import threading
import time

import pytest

from passkey.hooks import evaluate_hook_payload, install_hook, run_hook_check
from passkey.keychain import PasskeyError, save_entry
from passkey.models import Entry
from passkey.mount import mount_env_fifo


class TestEphemeralFifoMount:
    """Tests for passkey.mount.mount_env_fifo."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO only")
    def test_streams_secrets_over_fifo_and_unlinks_cleanly(self, tmp_path):
        save_entry(
            Entry(
                name="app_secrets",
                fields={"DB_PASS": "fifo_secret_value_123"},
                config={"DB_HOST": "localhost"},
            )
        )
        fifo_path = tmp_path / ".env"
        errors: list[Exception] = []

        def _serve():
            try:
                mount_env_fifo(["app_secrets"], path=fifo_path, max_reads=2, quiet=True)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        worker = threading.Thread(target=_serve, daemon=True)
        worker.start()

        # Wait for FIFO node to appear
        deadline = time.monotonic() + 3.0
        while not fifo_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)

        assert fifo_path.exists()
        st = fifo_path.lstat()
        assert stat.S_ISFIFO(st.st_mode)
        assert st.st_mode & 0o777 == 0o600

        # Read #1
        first_read = fifo_path.read_text(encoding="utf-8")
        assert "DB_PASS='fifo_secret_value_123'" in first_read
        assert "DB_HOST='localhost'" in first_read

        # Rotate secret in keychain before Read #2 to prove fresh keychain streaming
        save_entry(
            Entry(
                name="app_secrets",
                fields={"DB_PASS": "rotated_fifo_secret_456"},
                config={"DB_HOST": "localhost"},
            ),
            is_update=True,
        )
        time.sleep(0.03)
        second_read = fifo_path.read_text(encoding="utf-8")
        assert "DB_PASS='rotated_fifo_secret_456'" in second_read

        worker.join(timeout=3.0)
        assert not worker.is_alive()
        assert errors == []
        # FIFO must be unlinked after exit
        assert not fifo_path.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO only")
    def test_refuses_unignored_path_in_git_repo(self, tmp_path):
        save_entry(Entry(name="svc", fields={"KEY": "val1234"}))
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)

        exposed_fifo = repo / ".env"
        with pytest.raises(PasskeyError, match="not gitignored"):
            mount_env_fifo(["svc"], path=exposed_fifo, max_reads=1, quiet=True)
        assert not exposed_fifo.exists()

        # Once .env is added to .gitignore, mounting succeeds
        (repo / ".gitignore").write_text(".env\n")
        worker = threading.Thread(
            target=lambda: mount_env_fifo(["svc"], path=exposed_fifo, max_reads=1, quiet=True),
            daemon=True,
        )
        worker.start()
        deadline = time.monotonic() + 3.0
        while not exposed_fifo.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        content = exposed_fifo.read_text(encoding="utf-8")
        assert "KEY='val1234'" in content
        worker.join(timeout=2.0)
        assert not exposed_fifo.exists()

    def test_clean_error_on_windows(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        with pytest.raises(PasskeyError, match="not supported on Windows"):
            mount_env_fifo(["svc"], path=tmp_path / ".env", max_reads=1)

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO only")
    def test_unbounded_mount_fails_fast_for_headless_agents(self, tmp_path, monkeypatch, capsys):
        from unittest.mock import patch

        from passkey.cli import main

        save_entry(Entry(name="svc", fields={"KEY": "val1234"}))
        fifo_path = tmp_path / ".env"

        # Non-TTY unbounded mount -> exit 2 with passkey run / --once --timeout guidance
        monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
        with (
            patch.object(sys, "argv", ["passkey", "mount", "svc", "--path", str(fifo_path)]),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "passkey run -q svc -- <command>" in err
        assert "--once --timeout" in err
        assert not fifo_path.exists()

        # PTY-backed agent (CLAUDECODE=1) also fails fast if unbounded
        monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
        monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
        monkeypatch.setenv("CLAUDECODE", "1")
        with (
            patch.object(sys, "argv", ["passkey", "mount", "svc", "--path", str(fifo_path)]),
            pytest.raises(SystemExit) as exc_agent,
        ):
            main()
        assert exc_agent.value.code == 2
        capsys.readouterr()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO only")
    def test_mount_timeout_expires_cleanly_and_unlinks_fifo(self, tmp_path, capsys):
        from unittest.mock import patch

        from passkey.cli import main

        save_entry(Entry(name="svc", fields={"KEY": "secret_timeout_val"}))
        fifo_path = tmp_path / ".env"

        start = time.monotonic()
        with (
            patch.object(
                sys,
                "argv",
                [
                    "passkey",
                    "mount",
                    "svc",
                    "--path",
                    str(fifo_path),
                    "--once",
                    "--timeout",
                    "0.12",
                    "-q",
                ],
            ),
            pytest.raises(SystemExit) as exc,
        ):
            main()
        elapsed = time.monotonic() - start
        assert exc.value.code == 1
        assert elapsed < 2.0
        err = capsys.readouterr().err
        assert "Timed out after 0.12s waiting for a reader" in err
        assert "secret_timeout_val" not in err
        assert not fifo_path.exists()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFO only")
    def test_mount_timeout_serves_prompt_reader_and_stale_fifo_gives_rm_hint(self, tmp_path):
        import os

        save_entry(Entry(name="svc", fields={"KEY": "prompt_reader_val"}))
        fifo_path = tmp_path / ".env"

        # 1. Stale pre-existing FIFO yields specific rm '<path>' guidance
        os.mkfifo(fifo_path, 0o600)
        with pytest.raises(PasskeyError, match=r"FIFO already exists.*rm"):
            mount_env_fifo(["svc"], path=fifo_path, max_reads=1, timeout=1.0, quiet=True)
        fifo_path.unlink()

        # 2. Bounded --timeout succeeds when reader opens promptly
        errors: list[Exception] = []

        def _serve():
            try:
                mount_env_fifo(["svc"], path=fifo_path, max_reads=1, timeout=2.0, quiet=True)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        worker = threading.Thread(target=_serve, daemon=True)
        worker.start()

        deadline = time.monotonic() + 2.0
        while not fifo_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)

        data = fifo_path.read_text(encoding="utf-8")
        assert "KEY='prompt_reader_val'" in data
        worker.join(timeout=2.0)
        assert not worker.is_alive()
        assert errors == []
        assert not fifo_path.exists()


class TestAgentHooks:
    """Tests for non-destructive hook installation and secret-exfiltration blocking."""

    def test_install_hook_is_non_destructive_and_idempotent(self, tmp_path):
        # Pre-populate Cursor hooks.json with an existing hook (like require-changelog.py)
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        hooks_file = cursor_dir / "hooks.json"
        hooks_file.write_text(
            json.dumps(
                {
                    "version": 1,
                    "hooks": {
                        "beforeShellExecution": [
                            {"command": ".cursor/hooks/require-changelog.py", "timeout": 15}
                        ]
                    },
                }
            )
        )

        installed_cursor = install_hook("cursor", project_dir=tmp_path)
        install_hook("cursor", project_dir=tmp_path)  # idempotent second call
        data = json.loads(installed_cursor.read_text())
        shell_hooks = data["hooks"]["beforeShellExecution"]
        assert len(shell_hooks) == 2
        assert shell_hooks[0]["command"] == ".cursor/hooks/require-changelog.py"
        assert shell_hooks[1]["command"] == "passkey hook check --tool cursor"

        claude_path = install_hook("claude", project_dir=tmp_path)
        assert claude_path == (tmp_path / ".claude" / "settings.json").resolve()
        assert "PreToolUse" in json.loads(claude_path.read_text())["hooks"]

        gemini_path = install_hook("gemini", project_dir=tmp_path)
        assert gemini_path == (tmp_path / ".gemini" / "settings.json").resolve()
        assert "BeforeTool" in json.loads(gemini_path.read_text())["hooks"]

    @pytest.mark.parametrize(
        "payload,expected_allowed",
        [
            ({"tool_input": {"file_path": "/app/.env"}}, False),
            ({"tool_input": {"file_path": "/app/.env.production"}}, False),
            ({"tool_input": {"file_path": "/app/.env.example"}}, True),
            ({"tool_input": {"file_path": "/app/.env.passkey"}}, True),
            ({"tool_input": {"file_path": "/app/mcp.json.backup"}}, False),
            ({"tool_input": {"file_path": "/app/team.enc"}}, False),
            ({"command": "cat .env"}, False),
            ({"command": "passkey export -"}, False),
            ({"command": "passkey export schema.json --no-secrets"}, True),
            ({"command": "passkey run prod -- pytest -q"}, True),
        ],
    )
    def test_evaluate_hook_payload_decisions(self, payload, expected_allowed):
        allowed, _ = evaluate_hook_payload(payload)
        assert allowed is expected_allowed

    def test_run_hook_check_cursor_and_claude_exit_codes(self, capsys):
        rc_deny = run_hook_check(
            tool="cursor",
            stdin_text=json.dumps({"command": "cat .env.local"}),
        )
        assert rc_deny == 2
        out = json.loads(capsys.readouterr().out)
        assert out["permission"] == "deny"

        rc_allow = run_hook_check(
            tool="claude",
            stdin_text=json.dumps({"tool_input": {"command": "pytest -q"}}),
        )
        assert rc_allow == 0
