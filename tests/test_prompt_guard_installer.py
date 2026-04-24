"""Tests for prompt-guard installer — highest-risk code path (writes to settings)."""

import json
from pathlib import Path
from unittest.mock import patch

from aifence.prompt_guard.installer import _HOOK_MARKER, install, uninstall


def _fake_which(name: str) -> str | None:
    if name == _HOOK_MARKER:
        return "/usr/local/bin/aifence-pg-hook"
    return None


class TestInstall:
    def test_creates_settings_with_three_hook_events(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        with patch("shutil.which", side_effect=_fake_which):
            result = install(settings_path)

        assert settings_path.exists()
        settings = json.loads(settings_path.read_text())
        assert "hooks" in settings
        assert "UserPromptSubmit" in settings["hooks"]
        assert "PreToolUse" in settings["hooks"]
        assert "PostToolUse" in settings["hooks"]
        assert len(result.errors) == 0
        assert result.files_modified

    def test_hook_command_uses_absolute_binary_path(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        with patch("shutil.which", side_effect=_fake_which):
            install(settings_path)

        settings = json.loads(settings_path.read_text())
        for event_entries in settings["hooks"].values():
            for entry in event_entries:
                for handler in entry["hooks"]:
                    assert "/usr/local/bin/aifence-pg-hook" == handler["command"]

    def test_hook_has_timeout_of_5(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        with patch("shutil.which", side_effect=_fake_which):
            install(settings_path)

        settings = json.loads(settings_path.read_text())
        for event_entries in settings["hooks"].values():
            for entry in event_entries:
                for handler in entry["hooks"]:
                    assert handler["timeout"] == 5

    def test_idempotent_second_install_is_noop(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        with patch("shutil.which", side_effect=_fake_which):
            install(settings_path)
            result2 = install(settings_path)

        assert "nothing changed" in result2.actions[0]
        assert not result2.files_modified

        # Only one set of entries per event after two installs.
        settings = json.loads(settings_path.read_text())
        assert len(settings["hooks"]["UserPromptSubmit"]) == 1

    def test_merges_with_existing_hooks(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        existing = {
            "hooks": {
                "Stop": [{"hooks": [{"type": "command", "command": "/usr/bin/mycheck.sh"}]}]
            }
        }
        settings_path.write_text(json.dumps(existing))

        with patch("shutil.which", side_effect=_fake_which):
            install(settings_path)

        settings = json.loads(settings_path.read_text())
        # Existing Stop hook preserved.
        assert "Stop" in settings["hooks"]
        assert settings["hooks"]["Stop"][0]["hooks"][0]["command"] == "/usr/bin/mycheck.sh"
        # Our hooks added.
        assert "UserPromptSubmit" in settings["hooks"]

    def test_preserves_non_hook_settings_keys(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        existing = {
            "permissions": {"deny": ["Read(**/.env)"]},
            "sandbox": {"filesystem": {"denyRead": ["**/.env"]}},
        }
        settings_path.write_text(json.dumps(existing))

        with patch("shutil.which", side_effect=_fake_which):
            install(settings_path)

        settings = json.loads(settings_path.read_text())
        assert settings["permissions"]["deny"] == ["Read(**/.env)"]
        assert "**/.env" in settings["sandbox"]["filesystem"]["denyRead"]

    def test_dry_run_does_not_write_file(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        with patch("shutil.which", side_effect=_fake_which):
            result = install(settings_path, dry_run=True)

        assert not settings_path.exists()
        assert not result.errors
        assert any("Would install" in a for a in result.actions)

    def test_errors_when_binary_not_found(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        with patch("shutil.which", return_value=None):
            result = install(settings_path)

        assert result.errors
        assert not settings_path.exists()

    def test_errors_on_malformed_json(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{bad json")

        with patch("shutil.which", side_effect=_fake_which):
            result = install(settings_path)

        assert result.errors

    def test_creates_parent_directory(self, tmp_path):
        settings_path = tmp_path / "deep" / "nested" / ".claude" / "settings.json"
        with patch("shutil.which", side_effect=_fake_which):
            install(settings_path)

        assert settings_path.exists()


class TestUninstall:
    def test_removes_all_prompt_guard_hook_events(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings = {
            "hooks": {
                "UserPromptSubmit": [
                    {"hooks": [{"type": "command", "command": "/usr/local/bin/aifence-pg-hook"}]}
                ],
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/aifence-pg-hook"}]}
                ],
            }
        }
        settings_path.write_text(json.dumps(settings))

        result = uninstall(settings_path)

        assert not result.errors
        remaining = json.loads(settings_path.read_text())
        assert "hooks" not in remaining

    def test_preserves_other_hooks_while_removing_ours(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings = {
            "hooks": {
                "UserPromptSubmit": [
                    {"hooks": [{"command": "/usr/local/bin/aifence-pg-hook"}]},
                    {"hooks": [{"command": "/usr/bin/other-hook.sh"}]},
                ]
            }
        }
        settings_path.write_text(json.dumps(settings))

        uninstall(settings_path)

        remaining = json.loads(settings_path.read_text())
        entries = remaining["hooks"]["UserPromptSubmit"]
        assert len(entries) == 1
        assert entries[0]["hooks"][0]["command"] == "/usr/bin/other-hook.sh"

    def test_noop_when_no_settings_file(self, tmp_path):
        result = uninstall(tmp_path / ".claude" / "settings.json")
        assert not result.errors
        assert "nothing to remove" in result.actions[0].lower()

    def test_noop_when_our_hooks_not_present(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings = {"hooks": {"Stop": [{"hooks": [{"command": "/usr/bin/other.sh"}]}]}}
        settings_path.write_text(json.dumps(settings))

        result = uninstall(settings_path)
        assert "nothing to remove" in result.actions[0].lower()
        # Stop hook untouched.
        remaining = json.loads(settings_path.read_text())
        assert "Stop" in remaining["hooks"]

    def test_errors_on_malformed_json(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings_path.write_text("{bad json")

        result = uninstall(settings_path)
        assert result.errors

    def test_removes_hooks_key_when_empty_after_removal(self, tmp_path):
        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings = {
            "permissions": {"deny": ["Read(**/.env)"]},
            "hooks": {
                "UserPromptSubmit": [
                    {"hooks": [{"command": "/usr/local/bin/aifence-pg-hook"}]}
                ]
            },
        }
        settings_path.write_text(json.dumps(settings))

        uninstall(settings_path)

        remaining = json.loads(settings_path.read_text())
        assert "hooks" not in remaining
        # Other keys preserved.
        assert "permissions" in remaining
