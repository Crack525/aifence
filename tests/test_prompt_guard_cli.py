"""Tests for the prompt-guard CLI subgroup."""

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from aifence.cli import main
from aifence.prompt_guard.installer import _HOOK_MARKER

# Test fixture tokens — split so static scanners don't flag them as real secrets
_STRIPE_KEY = "sk_li" + "ve_XXXXXXXXXXXXXXXXXXXXXXXX"


def _fake_which(name: str) -> str | None:
    return "/usr/local/bin/aifence-pg-hook" if name == _HOOK_MARKER else None


class TestPromptGuardInstallCommand:
    def test_install_creates_settings_file(self, tmp_path):
        runner = CliRunner()
        settings_path = tmp_path / ".claude" / "settings.json"

        with patch("shutil.which", side_effect=_fake_which):
            result = runner.invoke(
                main,
                [
                    "prompt-guard",
                    "install",
                    "--project",
                    "--path",
                    str(tmp_path),
                ],
            )

        assert result.exit_code == 0
        assert settings_path.exists()
        assert "installed" in result.output.lower()

    def test_install_dry_run_does_not_write(self, tmp_path):
        runner = CliRunner()
        settings_path = tmp_path / ".claude" / "settings.json"

        with patch("shutil.which", side_effect=_fake_which):
            result = runner.invoke(
                main,
                ["prompt-guard", "install", "--project", "--path", str(tmp_path), "--dry-run"],
            )

        assert result.exit_code == 0
        assert not settings_path.exists()
        assert "Would install" in result.output

    def test_install_exits_1_when_binary_not_found(self, tmp_path):
        runner = CliRunner()

        with patch("shutil.which", return_value=None):
            result = runner.invoke(
                main,
                ["prompt-guard", "install", "--project", "--path", str(tmp_path)],
            )

        assert result.exit_code == 1

    def test_prompt_guard_appears_in_main_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "prompt-guard" in result.output


class TestPromptGuardUninstallCommand:
    def test_uninstall_removes_hooks(self, tmp_path):
        import json

        settings_path = tmp_path / ".claude" / "settings.json"
        settings_path.parent.mkdir(parents=True)
        settings = {
            "hooks": {
                "UserPromptSubmit": [
                    {"hooks": [{"command": "/usr/local/bin/aifence-pg-hook"}]}
                ]
            }
        }
        settings_path.write_text(json.dumps(settings))

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["prompt-guard", "uninstall", "--project", "--path", str(tmp_path)],
        )

        assert result.exit_code == 0
        remaining = json.loads(settings_path.read_text())
        assert "hooks" not in remaining

    def test_uninstall_noop_when_no_file(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["prompt-guard", "uninstall", "--project", "--path", str(tmp_path)],
        )
        assert result.exit_code == 0
        assert "nothing" in result.output.lower()


class TestPromptGuardScanCommand:
    def test_scan_clean_text_exits_0(self):
        runner = CliRunner()
        result = runner.invoke(main, ["prompt-guard", "scan", "hello world"])
        assert result.exit_code == 0
        assert "No sensitive" in result.output

    def test_scan_detects_aws_key_exits_1(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["prompt-guard", "scan", "key is AKIAIOSFODNN7EXAMPLE"]
        )
        assert result.exit_code == 1
        assert "aws-access-key" in result.output

    def test_scan_shows_multiple_detector_ids(self):
        runner = CliRunner()
        text = "AKIAIOSFODNN7EXAMPLE and " + _STRIPE_KEY
        result = runner.invoke(main, ["prompt-guard", "scan", text])
        assert result.exit_code == 1
        assert "aws-access-key" in result.output
        assert "stripe-key" in result.output

    def test_scan_each_id_shown_once_even_with_duplicates(self):
        runner = CliRunner()
        # Two AWS keys in one text.
        text = "key1=AKIAIOSFODNN7EXAMPLE and key2=AKIAIOSFODNN7EXAMPLA"
        result = runner.invoke(main, ["prompt-guard", "scan", text])
        # aws-access-key should appear only once in output (deduped by id).
        assert result.output.count("aws-access-key") == 1
