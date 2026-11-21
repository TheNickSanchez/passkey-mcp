"""Tests for inline pk1: token sharing, upload, collision resolution, and legacy bundles."""

import base64
import io
import json
import os
import re
import sys
import zlib
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from passkey.cli import main
from passkey.cli.parser import create_parser
from passkey.hooks import evaluate_hook_payload
from passkey.interactive import prompt_secret
from passkey.keychain import PasskeyError, get_entry, save_entry
from passkey.models import Entry
from passkey.sharing import (
    _PASSPHRASE_WORDS,
    FLAG_EMBEDDED_KEY,
    FLAG_ZLIB,
    MAX_TOKEN_PAYLOAD_BYTES,
    TOKEN_PREFIX,
    TOKEN_VERSION,
    cmd_receive,
    cmd_share,
    cmd_upload,
    decode_share_token,
    encode_share_token,
    generate_passphrase,
    normalize_passphrase,
)


class TestGeneratePassphrase:
    def test_default_length(self):
        phrase = generate_passphrase()
        words = phrase.split("-")
        assert len(words) == 8  # default is now 8 words (~64 bits entropy)

    def test_custom_length(self):
        phrase = generate_passphrase(6)
        words = phrase.split("-")
        assert len(words) == 6

    def test_words_are_from_list(self):
        phrase = generate_passphrase()
        for word in phrase.split("-"):
            assert word in _PASSPHRASE_WORDS

    def test_uniqueness(self):
        phrases = {generate_passphrase() for _ in range(20)}
        assert len(phrases) == 20

    def test_format(self):
        phrase = generate_passphrase()
        assert all(c.isalpha() or c == "-" for c in phrase)
        assert not phrase.startswith("-")
        assert not phrase.endswith("-")

    def test_normalize_passphrase_spaces_and_case(self):
        phrase = "alpine-falcon-quartz-beacon-ember-lunar-spruce-cobalt"
        spaced = "  Alpine   falcon\nquartz beacon ember lunar spruce cobalt  "
        assert normalize_passphrase(spaced) == phrase
        # Non-wordlist custom passphrases must not be mangled
        custom = "My Custom Passphrase 123!"
        assert normalize_passphrase(custom) == custom


class TestWordlist:
    def test_has_at_least_256_words(self):
        assert len(_PASSPHRASE_WORDS) >= 256

    def test_all_lowercase(self):
        for word in _PASSPHRASE_WORDS:
            assert word.islower()

    def test_no_duplicates(self):
        assert len(_PASSPHRASE_WORDS) == len(set(_PASSPHRASE_WORDS))


class TestReceive:
    def test_no_double_bundle_import_log(self, tmp_path):
        """Regression: receive logged bundle_import twice (inner + outer)."""
        bundle = tmp_path / "shared.enc"
        bundle.write_bytes(b"PK01" + b"\x00" * 40)

        with (
            patch(
                "passkey.sharing.import_bundle",
                return_value={"created": 1, "updated": 0, "skipped": 0},
            ),
            patch("passkey.sharing.log_operation") as mock_log,
            patch("getpass.getpass", return_value="x" * 12),
        ):
            cmd_receive(str(bundle))

        # import_bundle logs bundle_import itself; cmd_receive must not add another
        mock_log.assert_not_called()


class TestPk1Codec:
    """Verify pk1: wire format framing, size, AAD authentication, and zip-bomb defense."""

    def test_roundtrip_and_compact_size_under_350_chars(self):
        entry = Entry(
            name="jamf_api_admin",
            fields={
                "JAMF_CLIENT_ID": "8f14e45f-ceea-467a-a8f7-1234567890ab",
                "JAMF_CLIENT_SECRET": "sec_live_9876543210abcdef9876543210",
            },
            config={"JAMF_URL": "https://corp.jamfcloud.com"},
            policy="session",
        )
        phrase = generate_passphrase()
        token = encode_share_token(entry, passphrase=phrase, shared_by="nick")

        assert token.startswith(TOKEN_PREFIX)
        assert re.fullmatch(r"pk1:[A-Za-z0-9_-]+", token)
        assert len(token) < 360

        # Decode with Slack/Teams whitespace, newlines,Quotes, and space-separated passphrase
        wrapped_token = f'  "{token[:80]}\n  {token[80:]}"  \n'
        spaced_phrase = phrase.replace("-", " ").upper()

        decoded, meta = decode_share_token(
            wrapped_token,
            passphrase_fn=lambda: spaced_phrase,
        )
        assert decoded.name == "jamf_api_admin"
        assert decoded.fields == entry.fields
        assert decoded.config == {"JAMF_URL": "https://corp.jamfcloud.com"}
        assert decoded.policy == "session"
        assert meta["shared_by"] == "nick"
        assert meta["shared_at"] is not None
        assert meta["embedded_key"] is False

    def test_no_passphrase_embedded_key_roundtrip(self):
        entry = Entry(name="stripe_dev", fields={"STRIPE_SECRET_KEY": "sk_test_51Nabc123456"})
        token = encode_share_token(entry, passphrase=None)

        called = False

        def _never_called() -> str:
            nonlocal called
            called = True
            return ""

        decoded, meta = decode_share_token(token, passphrase_fn=_never_called)
        assert called is False
        assert decoded.name == "stripe_dev"
        assert decoded.fields == {"STRIPE_SECRET_KEY": "sk_test_51Nabc123456"}
        assert meta["embedded_key"] is True

    def test_wrong_passphrase_fails_cleanly(self):
        entry = Entry(name="stripe", fields={"API_KEY": "sk_test_1234567890"})
        token = encode_share_token(entry, passphrase="correct-passphrase-1234")

        with pytest.raises(PasskeyError, match="wrong passphrase or corrupted token"):
            decode_share_token(token, passphrase_fn=lambda: "wrong-passphrase-9999")

    def test_aad_header_tamper_rejected(self):
        """Flipping flags or header bytes must fail AES-GCM tag verification via AAD."""
        entry = Entry(name="stripe", fields={"API_KEY": "sk_test_1234567890"})
        token = encode_share_token(entry, passphrase=None)

        b64 = token[len(TOKEN_PREFIX) :]
        raw = bytearray(base64.urlsafe_b64decode(b64 + "=" * ((-len(b64)) % 4)))
        # Toggle FLAG_ZLIB bit in header byte 1 (still within 0x03 valid flag mask,
        # so it reaches AESGCM.decrypt and must fail AAD authentication!)
        raw[1] ^= FLAG_ZLIB
        tampered = TOKEN_PREFIX + base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")

        with pytest.raises(PasskeyError, match="corrupted or tampered"):
            decode_share_token(tampered)

    def test_unknown_version_and_reserved_flags_rejected(self):
        entry = Entry(name="stripe", fields={"API_KEY": "sk_test_1234567890"})
        token = encode_share_token(entry, passphrase=None)
        b64 = token[len(TOKEN_PREFIX) :]
        orig = base64.urlsafe_b64decode(b64 + "=" * ((-len(b64)) % 4))

        bad_ver = bytearray(orig)
        bad_ver[0] = 2
        tok_ver = TOKEN_PREFIX + base64.urlsafe_b64encode(bytes(bad_ver)).rstrip(b"=").decode("ascii")
        with pytest.raises(PasskeyError, match="Unsupported share token version"):
            decode_share_token(tok_ver)

        bad_flags = bytearray(orig)
        bad_flags[1] = 0x04
        tok_flags = TOKEN_PREFIX + base64.urlsafe_b64encode(bytes(bad_flags)).rstrip(b"=").decode("ascii")
        with pytest.raises(PasskeyError, match="Unsupported share token flags"):
            decode_share_token(tok_flags)

    def test_zip_bomb_payload_exceeding_256kib_rejected(self):
        """A valid GCM-authenticated compressed stream > 256 KiB must be rejected safely."""
        key = os.urandom(32)
        nonce = os.urandom(12)
        flags = FLAG_ZLIB | FLAG_EMBEDDED_KEY
        header = bytes([TOKEN_VERSION, flags]) + key + nonce

        oversized_json = json.dumps(
            {
                "v": 1,
                "n": "bomb",
                "f": {"BIG": "A" * (MAX_TOKEN_PAYLOAD_BYTES + 4096)},
            }
        ).encode("utf-8")
        compressed = zlib.compress(oversized_json, level=9)
        assert len(compressed) < 2048  # Tiny wire payload

        ct = AESGCM(key).encrypt(nonce, compressed, b"pk1:" + header)
        bomb_token = (
            TOKEN_PREFIX
            + base64.urlsafe_b64encode(header + ct).rstrip(b"=").decode("ascii")
        )

        with pytest.raises(PasskeyError, match="exceeds maximum size"):
            decode_share_token(bomb_token)

    def test_invalid_entry_name_or_policy_in_token_rejected(self):
        for bad_payload, match_re in [
            ({"v": 1, "n": "../traversal", "f": {"K": "V"}}, "Invalid entry name"),
            ({"v": 1, "n": "__entries__", "f": {"K": "V"}}, "Invalid entry name"),
            ({"v": 1, "n": "valid_name", "f": {"K": "V"}, "p": "superadmin"}, "Invalid policy"),
        ]:
            key = os.urandom(32)
            nonce = os.urandom(12)
            header = bytes([TOKEN_VERSION, FLAG_ZLIB | FLAG_EMBEDDED_KEY]) + key + nonce
            ct = AESGCM(key).encrypt(
                nonce,
                zlib.compress(json.dumps(bad_payload).encode("utf-8"), 9),
                b"pk1:" + header,
            )
            tok = TOKEN_PREFIX + base64.urlsafe_b64encode(header + ct).rstrip(b"=").decode("ascii")
            with pytest.raises(PasskeyError, match=match_re):
                decode_share_token(tok)


class TestShareCliAndUx:
    """Verify fuzzy resolution, field filtering, checkbox defaults, clipboard, and -o bundles."""

    def test_cli_help_strings_for_share_and_upload(self):
        parser = create_parser()
        top_help = parser.format_help()
        assert "upload" in top_help
        assert "pk1:" in top_help

        sub_action = next(a for a in parser._actions if hasattr(a, "choices") and isinstance(a.choices, dict))
        share_help = sub_action.choices["share"].format_help()
        upload_help = sub_action.choices["upload"].format_help()
        assert "--no-passphrase" in share_help
        assert "--prompt-passphrase" in share_help
        assert "--fields" in share_help
        assert "--mode" in upload_help
        assert "--as" in upload_help

    def test_fuzzy_share_copies_token_and_prints_8_word_passphrase(self, capsys):
        save_entry(
            Entry(
                name="jamf_api_admin",
                fields={
                    "CLIENT_ID": "id_12345678",
                    "CLIENT_SECRET": "sec_top_secret_value_999",
                },
            )
        )

        copied_items: list[tuple[str, int]] = []

        def _fake_copy(text: str, timeout_seconds: int = 30) -> None:
            copied_items.append((text, timeout_seconds))

        # Mock interactive TTY with checkbox returning all pre-checked choices
        mock_cb = MagicMock()
        mock_cb.ask.return_value = ["CLIENT_ID", "CLIENT_SECRET"]

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("questionary.checkbox", return_value=mock_cb) as checkbox_spy,
            patch("passkey.sharing.copy_with_autoclear", side_effect=_fake_copy),
            patch.object(sys, "argv", ["passkey", "share", "jamf"]),
        ):
            main()

        # Verify all choices were pre-checked by default!
        _, cb_kwargs = checkbox_spy.call_args
        assert all(getattr(c, "checked", False) is True for c in cb_kwargs["choices"])

        assert len(copied_items) == 1
        token, timeout_sec = copied_items[0]
        assert token.startswith("pk1:")
        assert timeout_sec == 120

        out = capsys.readouterr().out
        assert "Shared 'jamf_api_admin' (2 fields," in out
        assert "Passphrase:" in out
        assert "Recipient runs: passkey upload" in out
        assert "sec_top_secret_value_999" not in out

        # Extract printed passphrase and verify round-trip decode
        m = re.search(r"Passphrase:\s+([a-z-]+)", out)
        assert m is not None
        phrase = m.group(1)
        decoded, _ = decode_share_token(token, passphrase_fn=lambda: phrase)
        assert decoded.name == "jamf_api_admin"
        assert decoded.fields == {
            "CLIENT_ID": "id_12345678",
            "CLIENT_SECRET": "sec_top_secret_value_999",
        }

    def test_field_filtering_positional_and_flag(self):
        save_entry(
            Entry(
                name="jamf_api_admin",
                fields={"CLIENT_ID": "cid_1", "CLIENT_SECRET": "csec_2", "EXTRA": "ex_3"},
                config={"JAMF_URL": "https://corp.jamfcloud.com"},
            )
        )

        # Positional single field filter (skips interactive checkbox!)
        tok1 = cmd_share("jamf_api_admin", fields=["CLIENT_ID"], no_passphrase=True, no_copy=True)
        assert isinstance(tok1, str)
        dec1, _ = decode_share_token(tok1)
        assert dec1.fields == {"CLIENT_ID": "cid_1"}
        assert dec1.config == {}

        # Comma-separated flag filter including config key
        tok2 = cmd_share(
            "jamf_api_admin",
            fields=["CLIENT_ID,CLIENT_SECRET", "JAMF_URL"],
            no_passphrase=True,
            no_copy=True,
        )
        assert isinstance(tok2, str)
        dec2, _ = decode_share_token(tok2)
        assert dec2.fields == {"CLIENT_ID": "cid_1", "CLIENT_SECRET": "csec_2"}
        assert dec2.config == {"JAMF_URL": "https://corp.jamfcloud.com"}

    def test_positional_second_entry_name_gives_helpful_multi_entry_error(self):
        save_entry(Entry(name="jamf_api_admin", fields={"CLIENT_ID": "cid_1"}))
        save_entry(Entry(name="stripe", fields={"STRIPE_SECRET_KEY": "sk_1"}))

        with pytest.raises(PasskeyError) as exc_info:
            cmd_share("jamf_api_admin", fields=["stripe"], no_copy=True)

        assert exc_info.value.error_code == "INVALID_USAGE"
        assert "matches another keychain entry" in str(exc_info.value)
        assert "passkey export" in str(exc_info.value)

    def test_no_passphrase_warns_on_stderr_and_uses_60s_clipboard_ttl(self, capsys):
        save_entry(Entry(name="stripe", fields={"API_KEY": "sk_test_abcdef1234"}))
        copied: list[tuple[str, int]] = []

        with patch(
            "passkey.sharing.copy_with_autoclear",
            side_effect=lambda t, timeout_seconds=30: copied.append((t, timeout_seconds)),
        ):
            tok = cmd_share("stripe", no_passphrase=True)

        captured = capsys.readouterr()
        assert "WARNING: --no-passphrase" in captured.err
        assert copied == [(tok, 60)]
        # Self-decrypting token must NOT be echoed to stdout when clipboard succeeded
        assert str(tok) not in captured.out

    def test_legacy_output_file_bundle_backwards_compatibility(self, tmp_path, capsys):
        save_entry(
            Entry(
                name="stripe_legacy",
                fields={"STRIPE_SECRET_KEY": "sk_test_legacy_bundle_val"},
                policy="prompt",
            )
        )
        out_file = tmp_path / "stripe_legacy.enc"

        written = cmd_share("stripe_legacy", output_path=str(out_file), shared_by="alice")
        assert written == out_file
        assert out_file.exists()
        assert out_file.read_bytes()[:4] == b"PK01"
        if sys.platform != "win32":
            assert (out_file.stat().st_mode & 0o777) == 0o600

        out_text = capsys.readouterr().out
        m = re.search(r"Passphrase:\s+([a-z-]+)", out_text)
        assert m is not None
        phrase = m.group(1)

        # Import into a fresh entry name via cmd_upload
        with patch("passkey.sharing._prompt_share_passphrase", return_value=phrase):
            res = cmd_upload(str(out_file), as_name="stripe_restored")

        assert res["status"] == "created"
        restored = get_entry("stripe_restored")
        assert restored is not None
        assert restored.fields == {"STRIPE_SECRET_KEY": "sk_test_legacy_bundle_val"}
        assert restored.policy == "prompt"
        assert "_shared_by" not in restored.config


class TestUploadAndCollisionModes:
    """Verify Landmine #2 argv guard, masked paste preview, and Landmine #3 collision modes."""

    @pytest.mark.parametrize(
        "argv_builder",
        [
            lambda tok: ["passkey", "upload", tok],
            lambda tok: ["passkey", "receive", tok],
            lambda tok: ["passkey", tok],
            lambda tok: ["passkey", "share", tok],
            lambda tok: ["passkey", "share", "stripe", tok],
        ],
    )
    def test_pk1_token_in_cli_argv_refused_without_echoing_secret(self, argv_builder, capsys):
        fake_tok = "pk1:SUPER_SENSITIVE_TOKEN_PAYLOAD_NEVER_ECHO_12345"
        for interactive_mode in (True, False):
            with (
                patch("passkey.interactive.is_interactive", return_value=interactive_mode),
                patch.object(sys, "argv", argv_builder(fake_tok)),
                pytest.raises(SystemExit) as exc,
            ):
                main()

            assert exc.value.code == 1
            captured = capsys.readouterr()
            assert "Refusing 'pk1:' share token in CLI arguments" in captured.err
            assert fake_tok not in captured.err
            assert fake_tok not in captured.out

    def test_upload_interactive_paste_creates_entry_with_masked_preview(self, capsys):
        src = Entry(
            name="resend_prod",
            fields={"RESEND_API_KEY": "re_live_super_secret_token_value_987654"},
            config={"REGION": "us-east-1"},
            policy="session",
        )
        phrase = generate_passphrase()
        tok = encode_share_token(src, passphrase=phrase, shared_by="nick")

        prompts = iter([tok, phrase])
        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("passkey.interactive.prompt_secret", side_effect=lambda *a, **kw: next(prompts)),
            patch.object(sys, "argv", ["passkey", "upload"]),
        ):
            main()

        out = capsys.readouterr().out
        assert "Shared entry: resend_prod" in out
        assert "nick" in out
        assert "RESEND_API_KEY" in out
        # Raw secret must NEVER appear in preview output
        assert "re_live_super_secret_token_value_987654" not in out

        saved = get_entry("resend_prod")
        assert saved is not None
        assert saved.fields == {"RESEND_API_KEY": "re_live_super_secret_token_value_987654"}
        assert saved.config == {"REGION": "us-east-1"}
        assert saved.policy == "session"

    def test_collision_merge_and_overwrite_preserve_existing_metadata(self):
        """Landmine #3: Merge & Overwrite must preserve created, policy, source, last_rotated, config."""
        original = Entry(
            name="aws_shared",
            fields={"AWS_ACCESS_KEY_ID": "AKIA_OLD", "UNSHARED_TOKEN": "keep_me_secret"},
            config={"AWS_REGION": "us-west-2", "CUSTOM_NOTE": "keep_config"},
            created="2025-01-15T10:00:00",
            source="import-mcp",
            last_rotated="2025-06-01T12:00:00",
            policy="prompt",
        )
        save_entry(original)

        incoming = Entry(
            name="aws_shared",
            fields={"AWS_ACCESS_KEY_ID": "AKIA_NEW", "AWS_SECRET_ACCESS_KEY": "sec_new"},
            config={"AWS_REGION": "eu-central-1"},
            policy="allow",
        )
        tok = encode_share_token(incoming, passphrase=None)

        # 1. --mode skip leaves original untouched
        with patch("passkey.interactive.prompt_secret", return_value=tok):
            res_skip = cmd_upload(mode="skip")
        assert res_skip["status"] == "skipped"
        after_skip = get_entry("aws_shared")
        assert after_skip is not None
        assert after_skip.fields["AWS_ACCESS_KEY_ID"] == "AKIA_OLD"

        # 2. --mode merge updates shared keys while keeping UNSHARED_TOKEN + metadata
        with patch("passkey.interactive.prompt_secret", return_value=tok):
            res_merge = cmd_upload(mode="merge")
        assert res_merge["status"] == "merged"
        after_merge = get_entry("aws_shared")
        assert after_merge is not None
        assert after_merge.fields == {
            "AWS_ACCESS_KEY_ID": "AKIA_NEW",
            "AWS_SECRET_ACCESS_KEY": "sec_new",
            "UNSHARED_TOKEN": "keep_me_secret",
        }
        assert after_merge.config == {"AWS_REGION": "eu-central-1", "CUSTOM_NOTE": "keep_config"}
        assert after_merge.created == "2025-01-15T10:00:00"
        assert after_merge.policy == "prompt"
        assert after_merge.source == "import-mcp"
        assert after_merge.last_rotated == "2025-06-01T12:00:00"

        # 3. --mode overwrite replaces fields while still preserving created, policy, source, last_rotated & unshared config
        with patch("passkey.interactive.prompt_secret", return_value=tok):
            res_ow = cmd_upload(mode="overwrite")
        assert res_ow["status"] == "overwritten"
        after_ow = get_entry("aws_shared")
        assert after_ow is not None
        assert after_ow.fields == {
            "AWS_ACCESS_KEY_ID": "AKIA_NEW",
            "AWS_SECRET_ACCESS_KEY": "sec_new",
        }
        assert "UNSHARED_TOKEN" not in after_ow.fields
        assert after_ow.config == {"AWS_REGION": "eu-central-1", "CUSTOM_NOTE": "keep_config"}
        assert after_ow.created == "2025-01-15T10:00:00"
        assert after_ow.policy == "prompt"
        assert after_ow.source == "import-mcp"
        assert after_ow.last_rotated == "2025-06-01T12:00:00"

    def test_interactive_collision_ask_rename_and_cancel(self):
        save_entry(Entry(name="stripe", fields={"API_KEY": "sk_existing"}))
        tok = encode_share_token(
            Entry(name="stripe", fields={"API_KEY": "sk_incoming"}),
            passphrase=None,
        )

        # Rename via interactive collision menu
        sel_mock = MagicMock()
        sel_mock.ask.return_value = "rename"
        txt_mock = MagicMock()
        txt_mock.ask.return_value = "stripe_teammate"

        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("passkey.interactive.prompt_secret", return_value=tok),
            patch("questionary.select", return_value=sel_mock),
            patch("questionary.text", return_value=txt_mock),
        ):
            res = cmd_upload(mode="ask")

        assert res["status"] == "created"
        assert res["entry"] == "stripe_teammate"
        assert get_entry("stripe").fields == {"API_KEY": "sk_existing"}
        assert get_entry("stripe_teammate").fields == {"API_KEY": "sk_incoming"}

        # Cancel via interactive collision menu
        cancel_mock = MagicMock()
        cancel_mock.ask.return_value = "cancel"
        with (
            patch("passkey.interactive.is_interactive", return_value=True),
            patch("passkey.interactive.prompt_secret", return_value=tok),
            patch("questionary.select", return_value=cancel_mock),
        ):
            res_cancel = cmd_upload(mode="ask")

        assert res_cancel["status"] == "cancelled"
        assert get_entry("stripe").fields == {"API_KEY": "sk_existing"}


class TestAgentBlockingAndPasteBuffering:
    """Verify agent hook blocking, require_interactive exit 2, and single-frame paste buffering."""

    @pytest.mark.parametrize(
        "shell_cmd",
        [
            "passkey share stripe",
            "passkey share",
            "passkey --no-input share stripe",
            "passkey upload",
            "passkey upload bundle.enc",
            "passkey receive shared.enc",
            "passkey entry share stripe",
        ],
    )
    def test_hooks_block_share_upload_and_receive(self, shell_cmd):
        allowed, reason = evaluate_hook_payload({"tool_input": {"command": shell_cmd}})
        assert allowed is False
        assert "Blocked by passkey hook" in reason

    @pytest.mark.parametrize(
        "argv",
        [
            ["passkey", "share"],
            ["passkey", "share", "stripe"],
            ["passkey", "upload"],
            ["passkey", "receive"],
        ],
    )
    def test_agent_subprocess_env_exits_2(self, argv, monkeypatch):
        monkeypatch.setenv("CLAUDECODE", "1")
        monkeypatch.delenv("PASSKEY_ALLOW_INTERACTIVE", raising=False)
        with patch.object(sys, "argv", argv), pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2

    def test_prompt_secret_drains_posix_paste_burst_in_single_render(self):
        """Pasting 500 chars into a POSIX fd must render once for the burst, stopping cleanly at newline."""
        r_fd, w_fd = os.pipe()
        try:
            pasted_token = "pk1:" + ("A" * 500)
            next_line = "next_prompt_data\n"
            os.write(w_fd, (pasted_token + "\n" + next_line).encode("ascii"))

            fake_stdin = MagicMock()
            fake_stdin.isatty.return_value = True
            fake_stdin.fileno.return_value = r_fd

            class _TtyStringIO(io.StringIO):
                def isatty(self) -> bool:
                    return True

            out_buf = _TtyStringIO()
            fake_termios = MagicMock()
            fake_termios.ECHO = 1
            fake_termios.ICANON = 2
            fake_termios.ISIG = 4
            fake_termios.IEXTEN = 8
            fake_termios.IXON = 16
            fake_termios.ICRNL = 32
            fake_termios.INLCR = 64
            fake_termios.VMIN = 0
            fake_termios.VTIME = 1
            fake_termios.TCSADRAIN = 1
            fake_termios.tcgetattr.return_value = [0, 0, 0, 0xFF, 0, 0, [0, 0]]

            with (
                patch.object(sys, "platform", "darwin"),
                patch.object(sys, "stdin", fake_stdin),
                patch.dict(sys.modules, {"termios": fake_termios}),
            ):
                result = prompt_secret("Paste pk1:... token", stream=out_buf)

            assert result == pasted_token
            # Count full-line redraws (\r\x1b[2K): initial prompt (1) + final forced mask on \n (1) = 2!
            # Without paste-burst draining, this would have been 506 redraws.
            redraws = out_buf.getvalue().count("\r\x1b[2K")
            assert redraws <= 3

            # Ensure bytes after '\n' were NOT consumed from the fd!
            remaining = os.read(r_fd, 64).decode("ascii")
            assert remaining == next_line
        finally:
            os.close(r_fd)
            os.close(w_fd)

    def test_prompt_secret_handles_posix_pipe_eof_without_trailing_newline(self):
        """True kernel EOF (os.read == b'') must return non-empty buffer or raise EOFError when empty."""

        class _TtyStringIO(io.StringIO):
            def isatty(self) -> bool:
                return True

        fake_termios = MagicMock()
        fake_termios.ECHO = 1
        fake_termios.ICANON = 2
        fake_termios.ISIG = 4
        fake_termios.IEXTEN = 8
        fake_termios.IXON = 16
        fake_termios.ICRNL = 32
        fake_termios.INLCR = 64
        fake_termios.VMIN = 0
        fake_termios.VTIME = 1
        fake_termios.TCSADRAIN = 1
        fake_termios.tcgetattr.return_value = [0, 0, 0, 0xFF, 0, 0, [0, 0]]

        # 1. Non-empty buffer followed immediately by write-end close (no '\n') returns buffer cleanly
        r_fd, w_fd = os.pipe()
        try:
            os.write(w_fd, b"pk1:EOF_WITHOUT_NEWLINE")
            os.close(w_fd)
            w_fd = -1

            fake_stdin = MagicMock()
            fake_stdin.isatty.return_value = True
            fake_stdin.fileno.return_value = r_fd

            with (
                patch.object(sys, "platform", "darwin"),
                patch.object(sys, "stdin", fake_stdin),
                patch.dict(sys.modules, {"termios": fake_termios}),
            ):
                assert prompt_secret("Token", stream=_TtyStringIO()) == "pk1:EOF_WITHOUT_NEWLINE"

            # 2. Empty pipe at EOF raises EOFError immediately
            with (
                patch.object(sys, "platform", "darwin"),
                patch.object(sys, "stdin", fake_stdin),
                patch.dict(sys.modules, {"termios": fake_termios}),
                pytest.raises(EOFError),
            ):
                prompt_secret("Token", stream=_TtyStringIO())
        finally:
            os.close(r_fd)
            if w_fd != -1:
                os.close(w_fd)
