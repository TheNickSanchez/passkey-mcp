"""Tests for passkey.clipboard module."""

from unittest.mock import MagicMock, patch

import passkey.clipboard as cb


class TestClipboard:
    def test_copy_to_clipboard(self):
        with patch.object(cb.pyperclip, 'copy') as mock_copy:
            cb.copy_to_clipboard('test_secret')
            mock_copy.assert_called_once_with('test_secret')

    def test_clear_clipboard(self):
        with patch.object(cb.pyperclip, 'copy') as mock_copy:
            cb.clear_clipboard()
            mock_copy.assert_called_once_with('')

    def test_clear_if_matches_clears_matching_secret(self):
        with patch.object(cb.pyperclip, 'paste', return_value='my_secret'),              patch.object(cb.pyperclip, 'copy') as mock_copy:
            cb._clipboard_secret = 'my_secret'
            cb._clear_if_matches()
            mock_copy.assert_called_once_with('')
            assert cb._clipboard_secret is None

    def test_clear_if_matches_preserves_different_content(self):
        with patch.object(cb.pyperclip, 'paste', return_value='new_user_content'),              patch.object(cb.pyperclip, 'copy') as mock_copy:
            cb._clipboard_secret = 'old_secret'
            cb._clear_if_matches()
            mock_copy.assert_not_called()
            assert cb._clipboard_secret is None

    def test_copy_with_autoclear_spawns_detached_and_timer(self):
        with patch.object(cb.pyperclip, 'copy') as mock_copy,              patch.object(cb, '_spawn_detached_clear') as mock_spawn,              patch('threading.Timer') as mock_timer:
            mock_timer_instance = MagicMock()
            mock_timer.return_value = mock_timer_instance

            cb.copy_with_autoclear('secret_val', timeout_seconds=15)

            mock_copy.assert_called_once_with('secret_val')
            mock_spawn.assert_called_once_with('secret_val', 15)
            mock_timer.assert_called_once()
            mock_timer_instance.start.assert_called_once()
