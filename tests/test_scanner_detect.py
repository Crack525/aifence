"""Tests for scanner and detect modules."""

from aifence.detect import ToolStatus, detect_tools
from aifence.scanner import scan_workspace


class TestDetectTools:
    def test_nothing_detected(self, tmp_path):
        tools = detect_tools(tmp_path)
        assert len(tools) == 5
        assert all(not t.detected for t in tools)

    def test_claude_detected(self, tmp_path):
        (tmp_path / ".claude").mkdir()
        tools = detect_tools(tmp_path)
        claude = next(t for t in tools if t.name == "Claude Code")
        assert claude.detected

    def test_cursor_detected_by_dir(self, tmp_path):
        (tmp_path / ".cursor").mkdir()
        tools = detect_tools(tmp_path)
        cursor = next(t for t in tools if t.name == "Cursor")
        assert cursor.detected

    def test_cursor_detected_by_ignorefile(self, tmp_path):
        (tmp_path / ".cursorignore").write_text("")
        tools = detect_tools(tmp_path)
        cursor = next(t for t in tools if t.name == "Cursor")
        assert cursor.detected

    def test_copilot_detected(self, tmp_path):
        (tmp_path / ".github").mkdir()
        tools = detect_tools(tmp_path)
        copilot = next(t for t in tools if t.name == "Copilot")
        assert copilot.detected

    def test_label_format(self):
        t = ToolStatus("TestTool", True, ".config")
        assert t.label == "TestTool (detected)"
        t2 = ToolStatus("TestTool", False, ".config")
        assert t2.label == "TestTool (not detected)"


class TestScanner:
    def test_finds_env_file(self, tmp_path):
        (tmp_path / ".env").write_text("SECRET=x")
        found = scan_workspace(tmp_path, [".env"])
        assert len(found) == 1
        assert str(found[0]) == ".env"

    def test_finds_nested_file(self, tmp_path):
        sub = tmp_path / "config"
        sub.mkdir()
        (sub / "secrets.json").write_text("{}")
        found = scan_workspace(tmp_path, ["secrets.json"])
        assert len(found) == 1

    def test_glob_pattern(self, tmp_path):
        (tmp_path / "server.pem").write_text("")
        (tmp_path / "client.pem").write_text("")
        (tmp_path / "readme.md").write_text("")
        found = scan_workspace(tmp_path, ["*.pem"])
        assert len(found) == 2

    def test_skips_git_dir(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / ".env").write_text("SECRET=x")
        found = scan_workspace(tmp_path, [".env"])
        assert len(found) == 0

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / ".env").write_text("")
        found = scan_workspace(tmp_path, [".env"])
        assert len(found) == 0

    def test_no_matches(self, tmp_path):
        (tmp_path / "readme.md").write_text("")
        found = scan_workspace(tmp_path, [".env", "*.pem"])
        assert found == []

    def test_env_dot_star_pattern(self, tmp_path):
        (tmp_path / ".env.local").write_text("")
        (tmp_path / ".env.production").write_text("")
        found = scan_workspace(tmp_path, [".env.*"])
        assert len(found) == 2
