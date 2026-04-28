"""aifence CLI — protect sensitive files from AI coding tools."""

import json
import os
from pathlib import Path

import click

from aifence.detect import detect_tools
from aifence.generators import GeneratorResult, claude, copilot, cursor, gemini, windsurf
from aifence.patterns import PATTERNS
from aifence.prompt_guard.cli import prompt_guard
from aifence.scanner import scan_workspace

_AUDIT_LOG = Path(os.environ.get("AIFENCE_AUDIT_LOG", Path.home() / ".aifence" / "audit.log"))

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
@click.option(
    "--fail-on-sensitive",
    is_flag=True,
    default=False,
    help="Exit with code 1 if sensitive files are found (for CI/CD pipelines).",
)
def scan(path: str, fail_on_sensitive: bool) -> None:
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
    if fail_on_sensitive and found:
        raise SystemExit(1)


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


@main.command()
@click.option(
    "--lines",
    default=50,
    show_default=True,
    help="Number of most recent audit entries to show.",
)
@click.option(
    "--event",
    default=None,
    help="Filter by event type: UserPromptSubmit, PreToolUse, PostToolUse.",
)
@click.option(
    "--decision",
    default=None,
    help="Filter by decision: block, redact, warn.",
)
def audit(lines: int, event: str | None, decision: str | None) -> None:
    """Show recent prompt-guard audit log entries."""
    if not _AUDIT_LOG.exists():
        click.echo("No audit log found. Run 'aifence prompt-guard install' to enable hooks.")
        return

    entries = []
    try:
        with _AUDIT_LOG.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as e:
        click.echo(f"Error reading audit log: {e}", err=True)
        raise SystemExit(1) from e

    if event:
        entries = [e for e in entries if e.get("event") == event]
    if decision:
        entries = [e for e in entries if e.get("decision") == decision]

    recent = entries[-lines:]
    if not recent:
        click.echo("No audit entries match the given filters.")
        return

    click.echo(f"\n  Audit log ({len(recent)} entries, {_AUDIT_LOG}):\n")
    decision_colors = {"block": "red", "redact": "yellow", "warn": "yellow"}
    for entry in recent:
        dec = entry.get("decision", "")
        color = decision_colors.get(dec, "white")
        ts = entry.get("ts", "")[:19].replace("T", " ")
        ev = entry.get("event", "")
        detectors = ", ".join(entry.get("detectors", []))
        tool = entry.get("tool", "")
        tool_str = f" [{tool}]" if tool else ""
        dec_padded = dec.upper().ljust(8)
        click.echo(
            f"  {ts}  {click.style(dec_padded, fg=color)}  {ev}{tool_str}  {detectors}"
        )
    click.echo()
