"""Generate Claude Code protections: permissions.deny + sandbox.filesystem.denyRead."""

import json
from pathlib import Path

from aifence.generators import GeneratorResult
from aifence.patterns import PATTERNS


def _permission_deny_rules(patterns: list[str]) -> list[str]:
    """Convert patterns to Claude Code permissions.deny format.

    Uses gitignore-style paths: non-rooted patterns get **/ prefix
    so they match at any depth (e.g. Read(**/.env) matches config/.env).
    """
    rules = []
    for p in patterns:
        if p.startswith("/") or p.startswith("**/"):
            rules.append(f"Read({p})")
        else:
            rules.append(f"Read(**/{p})")
    return rules


def _sandbox_deny_patterns(patterns: list[str]) -> list[str]:
    """Convert patterns to sandbox.filesystem.denyRead glob format."""
    # Sandbox uses glob patterns. Prefix with **/ for non-rooted patterns.
    result = []
    for p in patterns:
        if p.startswith("/") or p.startswith("**/"):
            result.append(p)
        else:
            result.append(f"**/{p}")
    return result


def generate(
    workspace: Path,
    patterns: list[str] | None = None,
    dry_run: bool = False,
) -> GeneratorResult:
    """Generate or merge Claude Code settings with protection rules."""
    patterns = patterns or PATTERNS
    result = GeneratorResult(tool_name="Claude Code")
    settings_path = workspace / ".claude" / "settings.json"

    deny_rules = _permission_deny_rules(patterns)
    sandbox_patterns = _sandbox_deny_patterns(patterns)

    if dry_run:
        result.actions.append(f"permissions.deny — {len(deny_rules)} Read rules would be added")
        result.actions.append(f"sandbox.denyRead — {len(sandbox_patterns)} patterns would be added")
        return result

    # Load existing settings or start fresh.
    settings: dict = {}
    if settings_path.exists():
        text = settings_path.read_text()
        if text.strip():
            try:
                settings = json.loads(text)
            except json.JSONDecodeError:
                result.errors.append(f"Malformed JSON in {settings_path} — skipped (fix manually)")
                return result

    # --- Merge permissions.deny ---
    permissions = settings.setdefault("permissions", {})
    existing_deny: list = permissions.get("deny", [])
    existing_set = set(existing_deny)
    added_deny = [r for r in deny_rules if r not in existing_set]
    permissions["deny"] = existing_deny + added_deny

    # --- Merge sandbox.filesystem.denyRead ---
    sandbox = settings.setdefault("sandbox", {})
    fs = sandbox.setdefault("filesystem", {})
    existing_dr: list = fs.get("denyRead", [])
    existing_dr_set = set(existing_dr)
    added_sandbox = [p for p in sandbox_patterns if p not in existing_dr_set]
    fs["denyRead"] = existing_dr + added_sandbox

    # Write back only if something changed.
    if added_deny or added_sandbox:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(settings, indent=2) + "\n")
        result.files_modified.append(str(settings_path.relative_to(workspace)))

    result.actions.append(
        f"permissions.deny — {len(added_deny)} Read rules added"
        f" ({len(existing_deny)} already existed)"
    )
    result.actions.append(
        f"sandbox.denyRead — {len(added_sandbox)} patterns added"
        f" ({len(existing_dr)} already existed)"
    )
    if not sandbox.get("enabled"):
        result.warnings.append(
            "Sandbox not enabled — run /sandbox in Claude Code for OS-level Bash protection"
        )
    return result
