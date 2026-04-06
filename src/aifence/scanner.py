"""Scan workspace for files matching sensitive patterns."""

import fnmatch
from pathlib import Path

# Directories to skip during scanning.
_SKIP_DIRS = {
    ".git", ".venv", "venv", ".tox", "dist", "build",
    "node_modules", "__pycache__",
    ".cursor", ".claude", ".windsurf", ".github", ".gemini",
    ".ruff_cache", ".pytest_cache",
}


def scan_workspace(workspace: Path, patterns: list[str]) -> list[Path]:
    """Walk the workspace and return files whose names match any pattern."""
    matches: list[Path] = []
    for path in _walk(workspace):
        name = path.name
        for pat in patterns:
            if fnmatch.fnmatch(name, pat):
                matches.append(path.relative_to(workspace))
                break
    matches.sort()
    return matches


def _walk(root: Path):
    """Yield all files under *root*, skipping common non-project dirs."""
    for entry in sorted(root.iterdir()):
        if entry.is_dir():
            if entry.name in _SKIP_DIRS:
                continue
            yield from _walk(entry)
        else:
            yield entry
