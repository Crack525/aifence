"""Generate .copilotignore."""

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
        filename=".copilotignore",
        tool_name="Copilot",
        warnings=["Agent mode ignores .copilotignore — completions context only"],
        patterns=patterns,
        dry_run=dry_run,
    )
