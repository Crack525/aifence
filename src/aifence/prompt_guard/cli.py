"""prompt-guard subcommand group for the aifence CLI."""

import re
import sys
from pathlib import Path

import click

from aifence.generators import GeneratorResult
from aifence.prompt_guard.detectors import (
    DEFAULT_CONFIG_PATH,
    _BUILTIN_DETECTORS,
    _load_config,
    _write_config,
    detect_all,
    get_detectors,
)
from aifence.prompt_guard.installer import install, uninstall


def _settings_path(project: bool, path: str) -> Path:
    if project:
        return Path(path).resolve() / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def _print_result(result: GeneratorResult) -> None:
    for action in result.actions:
        click.echo(f"  {click.style('✓', fg='green')} {action}")
    for warning in result.warnings:
        click.echo(f"  {click.style('⚠', fg='yellow')} {warning}")
    for error in result.errors:
        click.echo(f"  {click.style('✗', fg='red')} {error}")


@click.group("prompt-guard")
def prompt_guard() -> None:
    """Prevent sensitive content from being sent to Claude."""


@prompt_guard.command("install")
@click.option(
    "--project",
    is_flag=True,
    default=False,
    help="Install in .claude/settings.json (project) instead of ~/.claude/settings.json (global).",
)
@click.option(
    "--path",
    default=".",
    type=click.Path(exists=True),
    help="Workspace root (only used with --project).",
)
@click.option("--dry-run", is_flag=True, default=False, help="Preview without writing.")
def install_cmd(project: bool, path: str, dry_run: bool) -> None:
    """Install content-guard hooks in Claude Code settings."""
    target = _settings_path(project, path)
    scope = "project" if project else "global"
    click.echo(f"Installing prompt-guard hooks ({scope}: {target}) ...")
    result = install(target, dry_run=dry_run)
    _print_result(result)
    if result.errors:
        sys.exit(1)


@prompt_guard.command("uninstall")
@click.option("--project", is_flag=True, default=False)
@click.option("--path", default=".", type=click.Path(exists=True))
def uninstall_cmd(project: bool, path: str) -> None:
    """Remove prompt-guard hooks from Claude Code settings."""
    target = _settings_path(project, path)
    click.echo(f"Removing prompt-guard hooks from {target} ...")
    result = uninstall(target)
    _print_result(result)
    if result.errors:
        sys.exit(1)


@prompt_guard.command("scan")
@click.argument("text", required=False)
def scan_cmd(text: str | None) -> None:
    """Dry-run text against all detectors.

    Pass text as an argument, or pipe it via stdin.
    Exits 1 if any sensitive content is detected.
    """
    if text is None:
        if sys.stdin.isatty():
            raise click.UsageError("Provide TEXT argument or pipe text via stdin.")
        text = sys.stdin.read()

    detections = detect_all(text)
    if not detections:
        click.echo(click.style("No sensitive content detected.", fg="green"))
        return

    click.echo(click.style(f"Detected {len(detections)} match(es):", fg="red"))
    shown: set[str] = set()
    for d in detections:
        if d.id not in shown:
            click.echo(f"  {click.style('✗', fg='red')} {d.id}: {d.description}")
            shown.add(d.id)
    sys.exit(1)


# ---------------------------------------------------------------------------
# rules subgroup
# ---------------------------------------------------------------------------


@prompt_guard.group("rules")
def rules_group() -> None:
    """Manage secret-detection rules (custom patterns + disable built-ins).

    Custom rules and disabled built-ins are stored in:
      ~/.aifence/prompt_guard.toml

    Changes take effect immediately — no reinstall required.
    """


@rules_group.command("list")
def rules_list() -> None:
    """List all active detectors (built-ins + custom) and any that are disabled."""
    config = _load_config(DEFAULT_CONFIG_PATH)
    disabled: set[str] = set(config.get("disable", []))
    custom_ids = {r.get("id", "") for r in config.get("rules", [])}

    active = get_detectors()

    click.echo(click.style("Active detectors:", bold=True))
    for det_id, description, _ in active:
        tag = click.style(" [custom]", fg="cyan") if det_id in custom_ids else ""
        click.echo(f"  {click.style('●', fg='green')} {det_id}{tag}  —  {description}")

    if disabled:
        click.echo()
        click.echo(click.style("Disabled built-ins:", bold=True))
        for det_id in sorted(disabled):
            click.echo(f"  {click.style('○', fg='yellow')} {det_id}")


@rules_group.command("add")
@click.option("--id", "rule_id", required=True, help="Unique identifier for the rule.")
@click.option("--description", required=True, help="Human-readable description.")
@click.option("--pattern", required=True, help="Python regex pattern (unescaped, as you'd write in code).")
@click.option(
    "--flag",
    "flags",
    multiple=True,
    type=click.Choice(["ASCII", "IGNORECASE", "MULTILINE"], case_sensitive=False),
    help="Regex flags (repeatable).",
)
def rules_add(rule_id: str, description: str, pattern: str, flags: tuple[str, ...]) -> None:
    """Add a custom detection rule."""
    try:
        flag_int = 0
        for f in flags:
            flag_int |= getattr(re, f.upper())
        re.compile(pattern, flag_int)
    except re.error as exc:
        raise click.ClickException(f"Invalid regex pattern: {exc}") from exc

    config = _load_config(DEFAULT_CONFIG_PATH)
    rules: list[dict] = config.get("rules", [])

    builtin_ids = {det_id for det_id, _, _ in _BUILTIN_DETECTORS}
    if rule_id in builtin_ids:
        raise click.ClickException(
            f"'{rule_id}' is already a built-in detector. "
            "To replace it, first disable it: "
            f"aifence prompt-guard rules disable --id {rule_id}"
        )

    existing_ids = {r.get("id") for r in rules}
    if rule_id in existing_ids:
        raise click.ClickException(
            f"Rule '{rule_id}' already exists. Remove it first with: "
            f"aifence prompt-guard rules remove --id {rule_id}"
        )

    new_rule: dict = {"id": rule_id, "description": description, "pattern": pattern}
    if flags:
        new_rule["flags"] = [f.upper() for f in flags]
    rules.append(new_rule)
    config["rules"] = rules
    _write_config(config, DEFAULT_CONFIG_PATH)
    click.echo(
        f"  {click.style('✓', fg='green')} Added rule '{rule_id}' → {DEFAULT_CONFIG_PATH}"
    )


@rules_group.command("remove")
@click.option("--id", "rule_id", required=True, help="ID of the custom rule to remove.")
def rules_remove(rule_id: str) -> None:
    """Remove a custom rule by ID."""
    config = _load_config(DEFAULT_CONFIG_PATH)
    rules: list[dict] = config.get("rules", [])
    original_len = len(rules)
    config["rules"] = [r for r in rules if r.get("id") != rule_id]

    if len(config["rules"]) == original_len:
        raise click.ClickException(
            f"No custom rule with id '{rule_id}' found. "
            "To disable a built-in, use: aifence prompt-guard rules disable"
        )

    _write_config(config, DEFAULT_CONFIG_PATH)
    click.echo(f"  {click.style('✓', fg='green')} Removed rule '{rule_id}'")


@rules_group.command("disable")
@click.option("--id", "rule_id", required=True, help="ID of the built-in rule to disable.")
def rules_disable(rule_id: str) -> None:
    """Disable a built-in detector (e.g. to silence a noisy false positive)."""
    builtin_ids = {det_id for det_id, _, _ in _BUILTIN_DETECTORS}
    if rule_id not in builtin_ids:
        raise click.ClickException(
            f"'{rule_id}' is not a built-in detector. "
            "Use 'aifence prompt-guard rules list' to see available IDs."
        )

    config = _load_config(DEFAULT_CONFIG_PATH)
    disabled: list[str] = config.get("disable", [])
    if rule_id in disabled:
        click.echo(f"  {click.style('⚠', fg='yellow')} '{rule_id}' is already disabled.")
        return

    disabled.append(rule_id)
    config["disable"] = disabled
    _write_config(config, DEFAULT_CONFIG_PATH)
    click.echo(f"  {click.style('✓', fg='green')} Disabled built-in '{rule_id}'")


@rules_group.command("enable")
@click.option("--id", "rule_id", required=True, help="ID of a previously disabled built-in to re-enable.")
def rules_enable(rule_id: str) -> None:
    """Re-enable a previously disabled built-in detector."""
    config = _load_config(DEFAULT_CONFIG_PATH)
    disabled: list[str] = config.get("disable", [])
    if rule_id not in disabled:
        click.echo(f"  {click.style('⚠', fg='yellow')} '{rule_id}' is not currently disabled.")
        return

    config["disable"] = [d for d in disabled if d != rule_id]
    _write_config(config, DEFAULT_CONFIG_PATH)
    click.echo(f"  {click.style('✓', fg='green')} Re-enabled built-in '{rule_id}'")
