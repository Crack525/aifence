"""Detect which AI coding tools have config in the workspace."""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ToolStatus:
    name: str
    detected: bool
    config_path: str  # where the tool's config lives (relative)

    @property
    def label(self) -> str:
        return f"{self.name} ({'detected' if self.detected else 'not detected'})"


def detect_tools(workspace: Path) -> list[ToolStatus]:
    """Check which AI tools have configuration in the workspace."""
    return [
        ToolStatus(
            name="Claude Code",
            detected=(workspace / ".claude").is_dir(),
            config_path=".claude/settings.json",
        ),
        ToolStatus(
            name="Cursor",
            detected=(workspace / ".cursor").is_dir() or (workspace / ".cursorignore").is_file(),
            config_path=".cursorignore",
        ),
        ToolStatus(
            name="Copilot",
            detected=(workspace / ".github").is_dir() or (workspace / ".copilotignore").is_file(),
            config_path=".copilotignore",
        ),
        ToolStatus(
            name="Windsurf",
            detected=(workspace / ".windsurf").is_dir()
            or (workspace / ".windsurfignore").is_file(),
            config_path=".windsurfignore",
        ),
        ToolStatus(
            name="Gemini CLI",
            detected=(workspace / ".gemini").is_dir(),
            config_path="",
        ),
    ]
