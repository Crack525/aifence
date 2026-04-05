"""Generate .cursorignore."""

from pathlib import Path

from aifence.generators import GeneratorResult
from aifence.generators.ignorefile import generate_ignore


def generate(
    workspace: Path,
    patterns: list[str] | None = None,
    dry_run: bool = False,
) -> GeneratorResult:
    return generate_ignore(
        workspace=workspace,
        filename=".cursorignore",
        tool_name="Cursor",
        warnings=["Shell commands (cat .env) not blocked — Cursor limitation"],
        patterns=patterns,
        dry_run=dry_run,
    )
