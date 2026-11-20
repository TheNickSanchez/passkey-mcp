"""Tests for passkey.keychain module."""

import json
import sys
from unittest.mock import patch

import pytest

from passkey.keychain import (
    METADATA_KEY,
    SERVICE,
    delete_entry,
    get_entry,
    list_entries,
    save_entry,
)
from passkey.models import Entry


@pytest.fixture
def mock_keyring():
    """Mock keyring module."""
    with patch("passkey.keychain.keyring") as mock:
        mock.get_password.return_value = None
        yield mock


class TestListEntries:
    """Tests for list_entries()."""

    def test_returns_empty_when_no_metadata(self, mock_keyring):
        """Returns empty list when no entries exist."""
        mock_keyring.get_password.return_value = None
        assert list_entries() == []

    def test_returns_parsed_list(self, mock_keyring):
        """Returns sorted list from metadata JSON."""
        mock_keyring.get_password.return_value = '["slack", "jamf"]'
        assert list_entries() == ["jamf", "slack"]

    def test_returns_empty_for_empty_string(self, mock_keyring):
        """Returns empty list for empty string."""
        mock_keyring.get_password.return_value = ""
        assert list_entries() == []


class TestSaveEntry:
    """Tests for save_entry()."""

    def _read_index(self) -> list[str]:
        from passkey.keychain import _get_index_path

        path = _get_index_path()
        if not path.exists():
            return []
        raw = json.loads(path.read_text())
        assert raw["version"] == 2
        return sorted(raw["entries"].keys())

    def test_saves_entry_fields(self, mock_keyring):
        """Saves entry fields as JSON with metadata."""
        mock_keyring.get_password.return_value = None
        entry = Entry(name="test", fields={"KEY": "value"})

        save_entry(entry)

        # Verify entry was saved with correct structure
        calls = [c for c in mock_keyring.set_password.call_args_list if c[0][1] == "test"]
        assert len(calls) == 1
        saved_json = json.loads(calls[0][0][2])
        assert saved_json["fields"] == {"KEY": "value"}
        assert "_meta" in saved_json

    def test_updates_index_for_new_entry(self, mock_keyring):
        """Adds new entry name to the file index."""
        mock_keyring.get_password.return_value = None
        entry = Entry(name="new", fields={"K": "V"})

        save_entry(entry)

        assert "new" in self._read_index()

    def test_does_not_duplicate_existing_entry(self, mock_keyring):
        """Does not add duplicate entry to the index."""
        mock_keyring.get_password.return_value = '["existing"]'
        entry = Entry(name="existing", fields={"K": "V"})

        save_entry(entry)

        assert self._read_index() == ["existing"]


class TestFileIndex:
    """Tests for the file-based entry index (P3-5)."""

    def test_migrates_legacy_keychain_index(self, mock_keyring, isolated_data_dir):
        """First read moves the keychain-held __entries__ index into entries.json v2."""
        mock_keyring.get_password.return_value = '["alpha", "beta"]'

        assert list_entries() == ["alpha", "beta"]

        from passkey.keychain import _get_index_path

        path = _get_index_path()
        assert path.exists()
        saved = json.loads(path.read_text())
        assert saved["version"] == 2
        assert sorted(saved["entries"].keys()) == ["alpha", "beta"]
        assert saved["entries"]["alpha"]["hydrated"] is False
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        # Legacy keychain item removed
        mock_keyring.delete_password.assert_called_with(SERVICE, METADATA_KEY)

    def test_index_file_wins_over_keychain(self, mock_keyring, isolated_data_dir):
        """Once the file exists, the keychain is not consulted for the index."""
        from passkey.keychain import _get_index_path

        _get_index_path().parent.mkdir(parents=True, exist_ok=True)
        _get_index_path().write_text('["file-wins"]')
        mock_keyring.get_password.return_value = '["keychain-loses"]'

        assert list_entries() == ["file-wins"]

    def test_corrupted_index_raises(self, mock_keyring, isolated_data_dir):
        from passkey.keychain import EntryCorruptedError, _get_index_path

        _get_index_path().parent.mkdir(parents=True, exist_ok=True)
        _get_index_path().write_text("{corrupted")

        with pytest.raises(EntryCorruptedError, match="corrupted"):
            list_entries()


class TestGetAllEntries:
    """P3-6: bulk reads must not spam one 'read' op per entry."""

    def test_single_bulk_read_logged(self, mock_keyring, isolated_data_dir):
        from passkey.keychain import _get_index_path, get_all_entries

        _get_index_path().parent.mkdir(parents=True, exist_ok=True)
        _get_index_path().write_text('["a", "b", "c"]')
        mock_keyring.get_password.return_value = '{"K": "V"}'

        with patch("passkey.keychain.log_operation") as mock_log:
            entries = get_all_entries()

        assert len(entries) == 3
        read_ops = [c for c in mock_log.call_args_list if c[0][0] == "read"]
        assert len(read_ops) == 1
        assert read_ops[0].kwargs["details"]["bulk"] is True
        assert read_ops[0].kwargs["details"]["count"] == 3


class TestAuditLabels:
    """Regression: creates saved with is_update=True were logged as updates."""

    def test_new_entry_logged_as_create_even_with_is_update_true(self, mock_keyring):
        mock_keyring.get_password.return_value = None  # entry is new
        entry = Entry(name="fresh", fields={"K": "V"})

        with patch("passkey.keychain.log_operation") as mock_log:
            save_entry(entry, is_update=True)

        ops = [c.kwargs.get("operation", c[0][0] if c[0] else None)
               for c in mock_log.call_args_list]
        assert "create" in ops
        assert "update" not in ops

    def test_existing_entry_logged_as_update(self, mock_keyring):
        mock_keyring.get_password.return_value = '["existing"]'
        entry = Entry(name="existing", fields={"K": "V"})

        with patch("passkey.keychain.log_operation") as mock_log:
            save_entry(entry)

        ops = [c.kwargs.get("operation", c[0][0] if c[0] else None)
               for c in mock_log.call_args_list]
        assert "update" in ops
        assert "create" not in ops


class TestGetEntry:
    """Tests for get_entry()."""

    def test_returns_none_when_not_found(self, mock_keyring):
        """Returns None for non-existent entry."""
        mock_keyring.get_password.return_value = None
        assert get_entry("missing") is None

    def test_returns_entry_when_found(self, mock_keyring):
        """Returns parsed Entry when found."""
        mock_keyring.get_password.return_value = '{"TOKEN": "secret"}'
        entry = get_entry("found")
        assert entry is not None
        assert entry.name == "found"
        assert entry.fields == {"TOKEN": "secret"}

    def test_returns_none_for_empty_string(self, mock_keyring):
        """Returns None for empty string."""
        mock_keyring.get_password.return_value = ""
        assert get_entry("empty") is None

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX index regression")
    @pytest.mark.parametrize("blank", [None, ""])
    def test_blank_keyring_does_not_drop_index_row(
        self, mock_keyring, isolated_data_dir, blank
    ):
        """Locked/transient keychain must not delete the entries.json row."""
        from passkey.keychain import _get_index_path

        _get_index_path().parent.mkdir(parents=True, exist_ok=True)
        _get_index_path().write_text('["keep-me"]')
        mock_keyring.get_password.return_value = blank

        assert get_entry("keep-me") is None
        assert json.loads(_get_index_path().read_text()) == ["keep-me"]


class TestDeleteEntry:
    """Tests for delete_entry()."""

    def test_deletes_from_keyring(self, mock_keyring):
        """Calls keyring.delete_password."""
        mock_keyring.get_password.return_value = '["test"]'
        delete_entry("test")
        # (migration may also delete the legacy __entries__ item; use any_call)
        mock_keyring.delete_password.assert_any_call(SERVICE, "test")

    def test_updates_index_after_delete(self, mock_keyring):
        """Removes entry from the file index."""
        mock_keyring.get_password.return_value = '["test", "other"]'

        delete_entry("test")

        from passkey.keychain import _get_index_path

        saved_index = json.loads(_get_index_path().read_text())
        assert saved_index["version"] == 2
        assert "test" not in saved_index["entries"]
        assert "other" in saved_index["entries"]

    def test_returns_false_when_not_found(self, mock_keyring):
        """Returns False when entry doesn't exist."""
        from keyring.errors import PasswordDeleteError
        mock_keyring.delete_password.side_effect = PasswordDeleteError()

        result = delete_entry("missing")

        assert result is False

    def test_returns_true_on_success(self, mock_keyring):
        """Returns True on successful delete."""
        mock_keyring.get_password.return_value = '["test"]'

        result = delete_entry("test")

        assert result is True


class TestZeroKeychainMetadataIndex:
    """Verify entries.json v2 metadata index eliminates N+1 Keychain prompts and lazily upgrades v1."""

    def test_v2_index_updates_on_every_save_and_rejects_malformed_structures(
        self, isolated_data_dir
    ):
        from passkey.keychain import (
            EntryCorruptedError,
            PasskeyError,
            _get_index_path,
            get_entry_meta,
            rename_entry,
        )

        entry = Entry(
            name="stripe",
            fields={"STRIPE_SECRET_KEY": "sk_live_secret_val_123"},
            config={"STRIPE_API_BASE": "https://api.stripe.com"},
            policy="allow",
            source="manual",
        )
        save_entry(entry)

        idx_path = _get_index_path()
        raw_text = idx_path.read_text(encoding="utf-8")
        assert "sk_live_secret_val_123" not in raw_text
        assert "https://api.stripe.com" not in raw_text

        doc = json.loads(raw_text)
        assert doc["version"] == 2
        assert doc["entries"]["stripe"]["fields"] == ["STRIPE_SECRET_KEY"]
        assert doc["entries"]["stripe"]["config_keys"] == ["STRIPE_API_BASE"]
        assert doc["entries"]["stripe"]["policy"] == "allow"
        assert doc["entries"]["stripe"]["hydrated"] is True

        # Updating fields/policy/rotation must update entries.json v2 metadata row
        entry.fields["WEBHOOK_SECRET"] = "whsec_secret_999"
        entry.policy = "prompt"
        entry.rotate()
        save_entry(entry, is_update=True)

        meta = get_entry_meta("stripe")
        assert meta is not None
        assert meta.fields == ["STRIPE_SECRET_KEY", "WEBHOOK_SECRET"]
        assert meta.policy == "prompt"
        assert meta.last_rotated is not None

        # Renaming updates index cleanly
        renamed = Entry(
            name="stripe_prod",
            fields=entry.fields.copy(),
            config=entry.config.copy(),
            created=entry.created,
            source=entry.source,
            last_rotated=entry.last_rotated,
            policy=entry.policy,
        )
        rename_entry("stripe", renamed)
        assert get_entry_meta("stripe") is None
        assert get_entry_meta("stripe_prod") is not None

        # Reserved names raise PasskeyError
        with pytest.raises(PasskeyError, match="reserved"):
            get_entry_meta("__audit_hmac_key__")

        # Malformed v2 structures raise EntryCorruptedError
        for bad_doc in (
            '{"version": 99, "entries": {}}',
            '{"version": 2, "entries": []}',
            '{"version": 2, "entries": {"a": "not-a-dict"}}',
            '{"version": 2, "entries": {"a": {"fields": {"k": "v"}}}}',
            "[123, 456]",
            "42",
        ):
            idx_path.write_text(bad_doc, encoding="utf-8")
            with pytest.raises(EntryCorruptedError):
                list_entries()

    def test_legacy_v1_index_loads_without_keychain_reads_and_lazily_upgrades(
        self, isolated_data_dir, capsys
    ):
        import keyring as kr

        from passkey.cli import main
        from passkey.keychain import _get_index_path, get_all_entry_metas, get_entry_meta

        # Populate two real entries in keyring, then overwrite entries.json with legacy v1 list
        save_entry(
            Entry(
                name="alpha",
                fields={"ALPHA_KEY": "alpha_secret_111"},
                config={"ALPHA_HOST": "alpha.internal"},
                policy="session",
            )
        )
        save_entry(Entry(name="beta", fields={"BETA_KEY": "beta_secret_222"}))

        idx_path = _get_index_path()
        idx_path.write_text('["alpha", "beta"]', encoding="utf-8")

        # 1. list_entries(), `passkey list --names-only`, `passkey list`, `passkey list --json`
        #    must make ZERO Keychain calls on an unhydrated v1 index
        with patch.object(
            kr, "get_password", side_effect=AssertionError("Keychain touched on v1 list!")
        ):
            assert list_entries() == ["alpha", "beta"]
            unhydrated = get_all_entry_metas(hydrate_unmigrated=False)
            assert [m.hydrated for m in unhydrated] == [False, False]

            with patch.object(sys, "argv", ["passkey", "list", "--names-only"]):
                main()
            assert capsys.readouterr().out.strip().splitlines() == ["alpha", "beta"]

            with patch.object(sys, "argv", ["passkey", "list"]):
                main()
            human_out = capsys.readouterr().out
            assert "alpha" in human_out and "—" in human_out

            with patch.object(sys, "argv", ["passkey", "list", "--json"]):
                main()
            json_rows = json.loads(capsys.readouterr().out)
            assert [r["hydrated"] for r in json_rows] == [False, False]
            assert [r["field_count"] for r in json_rows] == [None, None]

        # 2. Accessing get_entry_meta("alpha") hydrates ONLY "alpha" and upgrades entries.json to v2
        real_get_pw = kr.get_password
        touched_keys: list[str] = []

        def _spy_get_pw(service: str, username: str):
            touched_keys.append(username)
            return real_get_pw(service, username)

        with patch.object(kr, "get_password", side_effect=_spy_get_pw):
            meta_alpha = get_entry_meta("alpha")

        assert touched_keys == ["alpha"]
        assert meta_alpha is not None
        assert meta_alpha.hydrated is True
        assert meta_alpha.fields == ["ALPHA_KEY"]
        assert meta_alpha.config_keys == ["ALPHA_HOST"]
        assert meta_alpha.policy == "session"

        upgraded_doc = json.loads(idx_path.read_text(encoding="utf-8"))
        assert upgraded_doc["version"] == 2
        assert upgraded_doc["entries"]["alpha"]["hydrated"] is True
        assert upgraded_doc["entries"]["beta"]["hydrated"] is False

        # 3. Reading get_entry("beta") backfills "beta" as hydrated in entries.json
        loaded_beta = get_entry("beta")
        assert loaded_beta is not None
        fully_hydrated_doc = json.loads(idx_path.read_text(encoding="utf-8"))
        assert fully_hydrated_doc["entries"]["beta"]["hydrated"] is True
        assert fully_hydrated_doc["entries"]["beta"]["fields"] == ["BETA_KEY"]

    def test_ten_entries_zero_keychain_touches_across_all_discovery_and_preflight_paths(
        self, tmp_path, isolated_data_dir, capsys
    ):
        import keyring as kr

        from passkey.audit import clear_logs, log_operation
        from passkey.cli import main
        from passkey.mcp_config import ADAPTERS
        from passkey.mcp_server import (
            passkey_entry_info,
            passkey_fields,
            passkey_validate_references,
        )

        # Save 10 hydrated entries with varied policies, secret fields, and config keys
        for i in range(10):
            pol = "prompt" if i % 3 == 0 else ("session" if i % 3 == 1 else "allow")
            save_entry(
                Entry(
                    name=f"svc_{i}",
                    fields={f"SECRET_KEY_{i}": f"super_secret_value_{i}_xyz"},
                    config={f"CONFIG_KEY_{i}": f"https://svc-{i}.internal.example"},
                    policy=pol,
                )
            )

        # Prepare a project repo with .env.passkey for preflight, project status, and ref validation
        repo_dir = tmp_path / "app_repo"
        (repo_dir / ".git").mkdir(parents=True)
        dotenv_ref = repo_dir / ".env.passkey"
        dotenv_ref.write_text(
            "APP_SECRET=passkey://svc_0/SECRET_KEY_0\n"
            "APP_URL=passkey://svc_2/CONFIG_KEY_2\n",
            encoding="utf-8",
        )
        export_out = tmp_path / "inventory_no_secrets.json"

        # Phase 1: With audit.log present on disk (10 create records), assert 0 Keychain calls!
        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
            patch.object(
                kr,
                "get_password",
                side_effect=AssertionError("Keychain touched!"),
            ),
        ):
            # 1. passkey list
            with patch.object(sys, "argv", ["passkey", "list"]):
                main()
            out_list = capsys.readouterr().out
            assert "svc_0" in out_list and "svc_9" in out_list

            # 2. passkey list --names-only
            with patch.object(sys, "argv", ["passkey", "list", "--names-only"]):
                main()
            names_lines = capsys.readouterr().out.strip().splitlines()
            assert len(names_lines) == 10

            # 3. passkey list --json
            with patch.object(sys, "argv", ["passkey", "list", "--json"]):
                main()
            list_json = json.loads(capsys.readouterr().out)
            assert len(list_json) == 10
            assert "super_secret_value_" not in json.dumps(list_json)

            # 4. passkey info <entry> --json
            with patch.object(sys, "argv", ["passkey", "info", "svc_0", "--json"]):
                main()
            info_json = json.loads(capsys.readouterr().out)
            assert info_json["name"] == "svc_0"
            assert info_json["fields"] == ["SECRET_KEY_0"]
            assert info_json["config_keys"] == ["CONFIG_KEY_0"]

            # 5. passkey check
            with (
                patch.object(
                    sys, "argv", ["passkey", "check", "svc_0", "SECRET_KEY_0", "CONFIG_KEY_0"]
                ),
                pytest.raises(SystemExit) as exc_chk,
            ):
                main()
            assert exc_chk.value.code == 0
            capsys.readouterr()

            # 6. passkey find
            with patch.object(
                sys, "argv", ["passkey", "find", "SECRET_KEY_3", "CONFIG_KEY_7", "--json"]
            ):
                main()
            find_json = json.loads(capsys.readouterr().out)
            assert find_json["all_found"] is True
            assert find_json["resolved_entries"] == ["svc_3", "svc_7"]

            # 7. passkey policy <entry> --json (read-only mode)
            with patch.object(sys, "argv", ["passkey", "policy", "svc_1", "--json"]):
                main()
            pol_json = json.loads(capsys.readouterr().out)
            assert pol_json["policy"] == "session"
            assert pol_json["updated"] is False

            # 8. passkey run <entry> --dry-run --json (with --env-file passkey:// references)
            with (
                patch.object(
                    sys,
                    "argv",
                    [
                        "passkey",
                        "run",
                        "svc_4",
                        "--env-file",
                        str(dotenv_ref),
                        "--dry-run",
                        "--json",
                        "--",
                        sys.executable,
                        "-V",
                    ],
                ),
                pytest.raises(SystemExit) as exc_dry,
            ):
                main()
            assert exc_dry.value.code == 0
            dry_json = json.loads(capsys.readouterr().out)
            assert dry_json["ready"] is True
            assert "APP_SECRET" in dry_json["injected_env_vars"]

            # 9. passkey project status --json
            with patch.object(
                sys,
                "argv",
                ["passkey", "project", "status", "--project-dir", str(repo_dir), "--json"],
            ):
                main()
            proj_json = json.loads(capsys.readouterr().out)
            assert proj_json["ready"] is True

            # 10. passkey lease list --json (no leases.json -> 0 Keychain touches)
            with patch.object(sys, "argv", ["passkey", "lease", "list", "--json"]):
                main()
            assert json.loads(capsys.readouterr().out) == []

            # 11. passkey audit --summary --json
            with patch.object(sys, "argv", ["passkey", "audit", "--summary", "--json"]):
                main()
            sum_json = json.loads(capsys.readouterr().out)
            assert sum_json["oldest_entry"] is not None

            # 12. passkey export out.json --no-secrets
            with patch.object(
                sys, "argv", ["passkey", "export", str(export_out), "--no-secrets"]
            ):
                main()
            capsys.readouterr()
            exported = json.loads(export_out.read_text(encoding="utf-8"))
            assert exported["entry_count"] == 10
            assert "super_secret_value_" not in json.dumps(exported)
            assert "internal.example" not in json.dumps(exported)

            # 13. MCP discovery & validation tools
            assert passkey_fields("svc_5") == ["SECRET_KEY_5"]
            mcp_info = passkey_entry_info("svc_5")
            assert mcp_info["exists"] is True
            assert mcp_info["config_keys"] == ["CONFIG_KEY_5"]
            val_res = passkey_validate_references(str(dotenv_ref))
            assert val_res["valid"] is True

            # 14. passkey doctor --deep --json with empty audit log -> literally 0 Keychain calls
            clear_logs()
            with patch.object(sys, "argv", ["passkey", "doctor", "--deep", "--json"]):
                main()
            doc_json = json.loads(capsys.readouterr().out)
            assert doc_json["summary"]["failed"] == 0
            assert any(c["name"] == "entry_age" for c in doc_json["checks"])

        # Phase 2: With audit.log populated, doctor --deep verifies HMAC using __audit_hmac_key__
        #          while touching ZERO of the 10 user secret entries!
        log_operation("create", "svc_0")
        real_get_pw = kr.get_password

        def _forbid_secret_entries(service: str, username: str):
            if username != "__audit_hmac_key__":
                raise AssertionError(f"Keychain secret entry touched: {username}!")
            return real_get_pw(service, username)

        with (
            patch.dict(ADAPTERS, {}, clear=True),
            patch("passkey.doctor.find_passkey_command", return_value="/usr/local/bin/passkey"),
            patch.object(kr, "get_password", side_effect=_forbid_secret_entries),
            patch.object(sys, "argv", ["passkey", "doctor", "--deep", "--json"]),
        ):
            main()
        doc_deep_with_audit = json.loads(capsys.readouterr().out)
        assert doc_deep_with_audit["summary"]["failed"] == 0
        assert any(
            c["name"] == "audit_integrity" and c["status"] == "pass"
            for c in doc_deep_with_audit["checks"]
        )
