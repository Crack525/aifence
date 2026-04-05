"""Gemini CLI — no protection mechanism available, warn only."""

from pathlib import Path

from aifence.generators import GeneratorResult


def generate(
    workspace: Path,
    patterns: list[str] | None = None,
    dry_run: bool = False,
) -> GeneratorResult:
    result = GeneratorResult(tool_name="Gemini CLI")
    result.errors.append("No protection mechanism available")
    return result
