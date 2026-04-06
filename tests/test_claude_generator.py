"""Tests for Claude Code config generator — highest risk code path."""

import json

from aifence.generators.claude import (
    _permission_deny_rules,
    _sandbox_deny_patterns,
    generate,
)


class TestPermissionDenyRules:
    def test_wraps_patterns_in_read_with_recursive_prefix(self):
        result = _permission_deny_rules([".env", "*.pem"])
        assert result == ["Read(**/.env)", "Read(**/*.pem)"]

    def test_empty_patterns(self):
        assert _permission_deny_rules([]) == []


class TestSandboxDenyPatterns:
    def test_prefixes_with_double_star(self):
        result = _sandbox_deny_patterns([".env", "*.pem"])
        assert result == ["**/.env", "**/*.pem"]

    def test_preserves_absolute_paths(self):
        result = _sandbox_deny_patterns(["/absolute/path"])
        assert result == ["/absolute/path"]

    def test_preserves_existing_double_star(self):
        result = _sandbox_deny_patterns(["**/credentials*"])
        assert result == ["**/credentials*"]


class TestGenerate:
    def test_creates_new_settings_file(self, tmp_path):
        result = generate(tmp_path)
        settings_path = tmp_path / ".claude" / "settings.json"
        assert settings_path.exists()
        settings = json.loads(settings_path.read_text())
        assert "Read(**/.env)" in settings["permissions"]["deny"]
        assert "**/.env" in settings["sandbox"]["filesystem"]["denyRead"]
        assert ".claude/settings.json" in result.files_modified
        assert len(result.errors) == 0

    def test_merges_with_existing_permissions(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        existing = {
            "permissions": {"deny": ["Read(**/.env)", "Write(important.txt)"]},
            "other_key": "preserved",
        }
        settings_path.write_text(json.dumps(existing))

        generate(tmp_path)
        settings = json.loads(settings_path.read_text())

        # Existing rules preserved.
        assert "Read(**/.env)" in settings["permissions"]["deny"]
        assert "Write(important.txt)" in settings["permissions"]["deny"]
        # New rules added (deduped).
        assert "Read(**/*.pem)" in settings["permissions"]["deny"]
        # No duplicate .env.
        assert settings["permissions"]["deny"].count("Read(**/.env)") == 1
        # Other keys preserved.
        assert settings["other_key"] == "preserved"

    def test_merges_with_existing_sandbox(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        existing = {
            "sandbox": {
                "enabled": True,
                "filesystem": {"denyRead": ["**/.env", "**/custom-secret"]},
            }
        }
        settings_path.write_text(json.dumps(existing))

        generate(tmp_path)
        settings = json.loads(settings_path.read_text())

        deny_read = settings["sandbox"]["filesystem"]["denyRead"]
        # Existing preserved.
        assert "**/custom-secret" in deny_read
        # No duplicate.
        assert deny_read.count("**/.env") == 1
        # New patterns added.
        assert "**/*.pem" in deny_read

    def test_empty_existing_file(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("")

        generate(tmp_path)
        settings = json.loads(settings_path.read_text())
        assert "Read(**/.env)" in settings["permissions"]["deny"]

    def test_malformed_json_aborts(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{invalid json")

        result = generate(tmp_path)
        assert len(result.errors) == 1
        assert "Malformed JSON" in result.errors[0]
        # File untouched.
        assert settings_path.read_text() == "{invalid json"

    def test_existing_empty_object(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{}")

        result = generate(tmp_path)
        settings = json.loads(settings_path.read_text())
        assert "permissions" in settings
        assert "sandbox" in settings
        assert len(result.errors) == 0

    def test_partial_sandbox_config(self, tmp_path):
        """Existing sandbox without filesystem key."""
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text(json.dumps({"sandbox": {"enabled": True}}))

        result = generate(tmp_path)
        settings = json.loads(settings_path.read_text())
        assert "filesystem" in settings["sandbox"]
        assert len(settings["sandbox"]["filesystem"]["denyRead"]) > 0
        # Sandbox already enabled — no warning about enabling it.
        assert not any("Sandbox not enabled" in w for w in result.warnings)

    def test_warns_when_sandbox_not_enabled(self, tmp_path):
        """When sandbox is not enabled, warn the user."""
        result = generate(tmp_path)
        settings_path = tmp_path / ".claude" / "settings.json"
        settings = json.loads(settings_path.read_text())
        # Sandbox not auto-enabled.
        assert "enabled" not in settings.get("sandbox", {})
        # Warning present.
        assert any("Sandbox not enabled" in w for w in result.warnings)

    def test_dry_run_does_not_write(self, tmp_path):
        result = generate(tmp_path, dry_run=True)
        assert not (tmp_path / ".claude" / "settings.json").exists()
        assert len(result.actions) == 2
        assert "would be added" in result.actions[0]

    def test_custom_patterns(self, tmp_path):
        generate(tmp_path, patterns=[".my-secret"])
        settings_path = tmp_path / ".claude" / "settings.json"
        settings = json.loads(settings_path.read_text())
        assert settings["permissions"]["deny"] == ["Read(**/.my-secret)"]
        assert settings["sandbox"]["filesystem"]["denyRead"] == ["**/.my-secret"]

    def test_idempotent(self, tmp_path):
        """Running generate twice produces same result."""
        generate(tmp_path)
        first = (tmp_path / ".claude" / "settings.json").read_text()

        generate(tmp_path)
        second = (tmp_path / ".claude" / "settings.json").read_text()

        assert first == second

    def test_permission_error_handled(self, tmp_path):
        """Read-only settings file produces error, not crash."""
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{}")
        settings_path.chmod(0o444)

        result = generate(tmp_path)
        assert len(result.errors) == 1
        assert "Permission denied" in result.errors[0]
        assert len(result.files_modified) == 0
