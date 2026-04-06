"""Tests for CLI init/scan behavior — tool detection gating and --all-tools."""

from click.testing import CliRunner

from aifence.cli import main


class TestInitToolGating:
    def test_skips_undetected_tools(self, tmp_path):
        """init should skip tools that aren't detected and have no config file."""
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        # All tools undetected, no config files exist → all skipped.
        assert "skipped" in result.output
        assert not (tmp_path / ".cursorignore").exists()
        assert not (tmp_path / ".copilotignore").exists()
        assert not (tmp_path / ".windsurfignore").exists()

    def test_generates_for_detected_tools(self, tmp_path):
        """init should generate configs for detected tools."""
        (tmp_path / ".cursor").mkdir()
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".cursorignore").exists()
        # Copilot not detected, no config → skipped.
        assert not (tmp_path / ".copilotignore").exists()

    def test_all_tools_generates_everything(self, tmp_path):
        """--all-tools should generate configs for all tools regardless of detection."""
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--path", str(tmp_path), "--all-tools"])
        assert result.exit_code == 0
        assert (tmp_path / ".cursorignore").exists()
        assert (tmp_path / ".copilotignore").exists()
        assert (tmp_path / ".windsurfignore").exists()
        assert "skipped" not in result.output

    def test_updates_existing_config_even_if_not_detected(self, tmp_path):
        """If a config file exists but tool isn't detected, still merge patterns."""
        (tmp_path / ".copilotignore").write_text("*.log\n")
        runner = CliRunner()
        result = runner.invoke(main, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        content = (tmp_path / ".copilotignore").read_text()
        assert "*.log" in content  # preserved
        assert ".env" in content  # patterns merged


class TestScanShowsAllTools:
    def test_scan_shows_all_tools(self, tmp_path):
        """scan should show all tools regardless of detection."""
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "Claude Code" in result.output
        assert "Cursor" in result.output
        assert "Copilot" in result.output
        assert "Windsurf" in result.output
        assert "Gemini CLI" in result.output
        # scan never skips.
        assert "skipped" not in result.output
