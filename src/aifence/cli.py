"""aifence CLI — protect sensitive files from AI coding tools."""

from pathlib import Path

import click

from aifence.detect import detect_tools
from aifence.generators import GeneratorResult, claude, copilot, cursor, gemini, windsurf
from aifence.patterns import PATTERNS
from aifence.prompt_guard.cli import prompt_guard
from aifence.scanner import scan_workspace

# Map tool names to their generators and config file paths.
_GENERATORS = {
    "Claude Code": claude,
    "Cursor": cursor,
    "Copilot": copilot,
    "Windsurf": windsurf,
    "Gemini CLI": gemini,
}

_CONFIG_FILES = {
    "Claude Code": ".claude/settings.json",
    "Cursor": ".cursorignore",
    "Copilot": ".copilotignore",
    "Windsurf": ".windsurfignore",
    "Gemini CLI": "",
}


def _config_exists(workspace: Path, tool_name: str) -> bool:
    """Check if a tool's config file already exists in the workspace."""
    config_file = _CONFIG_FILES.get(tool_name, "")
    if not config_file:
        return False
    return (workspace / config_file).exists()


def _print_scan(found: list[Path]) -> None:
    if found:
        click.echo(f"\n  Found {len(found)} sensitive file(s):")
        for f in found:
            click.echo(f"    {f}")
    else:
        click.echo("\n  No sensitive files found matching default patterns.")


def _print_result(result: GeneratorResult, detected: bool) -> None:
    status = "detected" if detected else "not detected"
    click.echo(f"\n  {result.tool_name} ({status}):")
    for action in result.actions:
        click.echo(f"    {click.style('✓', fg='green')} {action}")
    for warning in result.warnings:
        click.echo(f"    {click.style('⚠', fg='yellow')} {warning}")
    for error in result.errors:
        click.echo(f"    {click.style('✗', fg='red')} {error}")


def _print_skipped(tool_name: str) -> None:
    click.echo(f"\n  {tool_name} (not detected):")
    click.echo(f"    {click.style('—', fg='cyan')} skipped — use --all-tools to generate anyway")


@click.group()
@click.version_option()
def main() -> None:
    """Protect sensitive files from AI coding tools."""


main.add_command(prompt_guard)


@main.command()
@click.option("--path", default=".", type=click.Path(exists=True), help="Workspace path to scan.")
def scan(path: str) -> None:
    """Scan workspace and show exposure (dry-run)."""
    workspace = Path(path).resolve()
    click.echo("Scanning for sensitive files...")
    found = scan_workspace(workspace, PATTERNS)
    _print_scan(found)

    click.echo("\n  AI Tool Protection:")
    tools = detect_tools(workspace)
    for tool in tools:
        gen = _GENERATORS[tool.name]
        result = gen.generate(workspace, dry_run=True)
        _print_result(result, tool.detected)

    click.echo()


@main.command()
@click.option("--path", default=".", type=click.Path(exists=True), help="Workspace path.")
@click.option(
    "--all-tools",
    is_flag=True,
    default=False,
    help="Generate configs for all tools, not just detected ones.",
)
def init(path: str, all_tools: bool) -> None:
    """Scan workspace, show exposure, and apply protections."""
    workspace = Path(path).resolve()
    click.echo("Scanning for sensitive files...")
    found = scan_workspace(workspace, PATTERNS)
    _print_scan(found)

    click.echo("\n  Applying protections...\n")
    tools = detect_tools(workspace)
    files_modified: list[str] = []

    for tool in tools:
        gen = _GENERATORS[tool.name]
        should_generate = tool.detected or all_tools or _config_exists(workspace, tool.name)
        if not should_generate:
            _print_skipped(tool.name)
            continue

        result = gen.generate(workspace)
        _print_result(result, tool.detected)
        files_modified.extend(result.files_modified)

    if files_modified:
        click.echo("\n  Files modified:")
        for f in files_modified:
            click.echo(f"    {f}")

    click.echo(
        f"\n  Protected patterns: {', '.join(PATTERNS[:6])}..."
        if len(PATTERNS) > 6
        else f"\n  Protected patterns: {', '.join(PATTERNS)}"
    )
    click.echo()
