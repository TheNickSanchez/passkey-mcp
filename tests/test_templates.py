"""Tests for secret templates."""

import json
from unittest.mock import patch

from passkey.templates import (
    BUILTIN_TEMPLATES,
    get_template,
    list_templates,
    save_custom_template,
)


class TestBuiltinTemplates:
    def test_all_have_name(self):
        for t in BUILTIN_TEMPLATES:
            assert "name" in t
            assert isinstance(t["name"], str)

    def test_all_have_fields(self):
        for t in BUILTIN_TEMPLATES:
            assert "fields" in t
            assert len(t["fields"]) > 0

    def test_all_fields_have_name(self):
        for t in BUILTIN_TEMPLATES:
            for field in t["fields"]:
                assert "name" in field
                assert isinstance(field["name"], str)

    def test_all_have_description(self):
        for t in BUILTIN_TEMPLATES:
            assert "description" in t

    def test_expected_templates_exist(self):
        names = {t["name"] for t in BUILTIN_TEMPLATES}
        expected = {"github", "aws", "slack", "openai", "stripe", "vercel", "postgres", "mysql"}
        assert expected.issubset(names)


class TestListTemplates:
    def test_returns_list(self):
        result = list_templates()
        assert isinstance(result, list)
        assert len(result) >= 8  # at least the built-ins

    def test_sorted_by_name(self):
        result = list_templates()
        names = [t["name"] for t in result]
        assert names == sorted(names)

    def test_includes_all_builtins(self):
        result = list_templates()
        names = {t["name"] for t in result}
        for t in BUILTIN_TEMPLATES:
            assert t["name"] in names


class TestGetTemplate:
    def test_existing_template(self):
        template = get_template("github")
        assert template is not None
        assert template["name"] == "github"
        assert len(template["fields"]) > 0

    def test_nonexistent_template(self):
        template = get_template("nonexistent")
        assert template is None

    def test_fields_have_required_keys(self):
        template = get_template("aws")
        assert template is not None
        for field in template["fields"]:
            assert "name" in field
            assert "secret" in field


class TestSaveCustomTemplate:
    def test_save_and_load(self, tmp_path):
        template = {
            "name": "custom-test",
            "description": "Test template",
            "fields": [
                {"name": "API_KEY", "description": "Key", "secret": True},
                {"name": "API_URL", "description": "URL", "secret": False},
            ],
        }

        with patch("passkey.templates._get_templates_dir", return_value=tmp_path):
            save_custom_template(template)
            # Verify file was created
            assert (tmp_path / "custom-test.json").exists()

            # Verify content
            data = json.loads((tmp_path / "custom-test.json").read_text())
            assert data["name"] == "custom-test"
            assert len(data["fields"]) == 2

    def test_strips_secret_values(self, tmp_path):
        template = {
            "name": "stripper",
            "description": "Test",
            "fields": [
                {"name": "KEY", "secret": True, "value": "supersecret"},
            ],
        }

        with patch("passkey.templates._get_templates_dir", return_value=tmp_path):
            save_custom_template(template)
            data = json.loads((tmp_path / "stripper.json").read_text())
            assert "value" not in data["fields"][0]

    def test_save_rejects_shadowing_builtin(self, tmp_path):
        import pytest
        from passkey.keychain import PasskeyError
        custom = {
            "name": "github",
            "description": "Custom GitHub",
            "fields": [{"name": "MY_CUSTOM_FIELD", "secret": True}],
        }

        with patch("passkey.templates._get_templates_dir", return_value=tmp_path):
            with pytest.raises(PasskeyError, match="Cannot overwrite built-in template"):
                save_custom_template(custom)

    def test_list_templates_protects_builtin_precedence(self, tmp_path):
        # Even if a rogue file exists in templates dir
        (tmp_path / "github.json").write_text(json.dumps({
            "name": "github",
            "description": "Rogue GitHub",
            "fields": [{"name": "ROGUE_FIELD", "secret": False}],
        }))

        with patch("passkey.templates._get_templates_dir", return_value=tmp_path):
            templates = list_templates()
            github = next(t for t in templates if t["name"] == "github")
            assert github["description"] != "Rogue GitHub"
            field_names = [f["name"] for f in github["fields"]]
            assert "GITHUB_TOKEN" in field_names
            assert "ROGUE_FIELD" not in field_names
