"""Tests for passkey.completion module."""

from unittest.mock import patch

import pytest

from passkey.completion import print_completion, print_setup_instructions


class TestPrintCompletion:
    def test_bash_script(self, capsys):
        print_completion("bash")
        captured = capsys.readouterr()
        assert "_passkey_completions" in captured.out
        assert "complete -F" in captured.out

    def test_zsh_script(self, capsys):
        print_completion("zsh")
        captured = capsys.readouterr()
        assert "_passkey" in captured.out
        assert "compdef" in captured.out

    def test_fish_script(self, capsys):
        print_completion("fish")
        captured = capsys.readouterr()
        assert "__passkey_entries" in captured.out
        assert "complete -c passkey" in captured.out

    def test_unknown_shell(self):
        from passkey.keychain import PasskeyError
        with pytest.raises(PasskeyError) as exc_info:
            print_completion("powershell")
        assert "Unknown shell" in str(exc_info.value)

    def test_all_scripts_contain_new_commands(self):
        from passkey.completion import _BASH_SCRIPT, _FISH_SCRIPT, _ZSH_SCRIPT
        for script in [_BASH_SCRIPT, _FISH_SCRIPT, _ZSH_SCRIPT]:
            for cmd in ["generate", "template", "share", "receive", "rotate"]:
                assert cmd in script, f"'{cmd}' missing from script"


class TestPrintSetupInstructions:
    def test_prints_instructions(self, capsys):
        print_setup_instructions()
        captured = capsys.readouterr()
        assert "Bash" in captured.out
        assert "Zsh" in captured.out
        assert "Fish" in captured.out
        assert "passkey completion --bash" in captured.out
        assert "passkey completion --zsh" in captured.out
        assert "passkey completion --fish" in captured.out


class TestGetEntries:
    def test_returns_entries_on_success(self):
        from passkey.completion import _get_entries
        with patch("passkey.completion.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "entry1\nentry2\nentry3\n"
            assert _get_entries() == ["entry1", "entry2", "entry3"]

    def test_returns_empty_on_failure(self):
        from passkey.completion import _get_entries
        with patch("passkey.completion.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            assert _get_entries() == []

    def test_returns_empty_on_exception(self):
        from passkey.completion import _get_entries
        with patch("passkey.completion.subprocess.run", side_effect=TimeoutError()):
            assert _get_entries() == []

    def test_strips_empty_lines(self):
        from passkey.completion import _get_entries
        with patch("passkey.completion.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "entry1\n\n\nentry2\n\n"
            assert _get_entries() == ["entry1", "entry2"]
