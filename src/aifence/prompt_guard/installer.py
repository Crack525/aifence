"""Install and uninstall prompt-guard hooks in Claude Code settings files."""

import json
import shutil
from pathlib import Path

from aifence.generators import GeneratorResult

# Unique string present in every hook command we install.
# Used for idempotency checks and targeted removal.
_HOOK_MARKER = "aifence-pg-hook"

# Tools whose input we redact in PreToolUse.
_REDACT_TOOLS = "Bash|Write|Edit|WebFetch|WebSearch"

# Timeout in seconds Claude Code will allow the hook to run.
_HOOK_TIMEOUT = 5


def _hook_binary() -> str | None:
    """Return the absolute path of the aifence-pg-hook binary, or None."""
    return shutil.which(_HOOK_MARKER)


def _build_hook_config(binary: str) -> dict:
    """Return the hooks dict to merge into Claude Code settings."""
    handler = {"type": "command", "command": binary, "timeout": _HOOK_TIMEOUT}
    return {
        "UserPromptSubmit": [{"hooks": [handler]}],
        "PreToolUse": [{"matcher": _REDACT_TOOLS, "hooks": [handler]}],
        "PostToolUse": [{"matcher": _REDACT_TOOLS, "hooks": [handler]}],
    }


def _entry_has_marker(entry: dict) -> bool:
    """Return True if any handler inside this matcher group is ours."""
    return any(_HOOK_MARKER in h.get("command", "") for h in entry.get("hooks", []))


def install(settings_path: Path, dry_run: bool = False) -> GeneratorResult:
    """Merge prompt-guard hooks into *settings_path*.

    Idempotent — re-running install after the hooks are already present is a
    no-op. Existing hooks are preserved; only new event groups are appended.
    """
    result = GeneratorResult(tool_name="prompt-guard")

    binary = _hook_binary()
    if not binary:
        result.errors.append(
            f"{_HOOK_MARKER} not found in PATH. "
            "Ensure aifence is installed (pip install aifence) then retry."
        )
        return result

    hook_config = _build_hook_config(binary)

    if dry_run:
        events = ", ".join(hook_config)
        result.actions.append(f"Would install hooks ({events}) → {settings_path}")
        result.actions.append(f"Hook binary: {binary}")
        return result

    # Load or create settings.
    settings: dict = {}
    if settings_path.exists():
        text = settings_path.read_text()
        if text.strip():
            try:
                settings = json.loads(text)
            except json.JSONDecodeError:
                result.errors.append(
                    f"Malformed JSON in {settings_path} — fix manually and retry"
                )
                return result

    hooks = settings.setdefault("hooks", {})
    added: list[str] = []

    for event, new_entries in hook_config.items():
        existing: list = hooks.get(event, [])
        # Skip if our marker is already present in any existing entry.
        if any(_entry_has_marker(e) for e in existing):
            continue
        hooks[event] = existing + new_entries
        added.append(event)

    if not added:
        result.actions.append("Hooks already installed — nothing changed")
        return result

    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    result.actions.append(f"Hooks installed: {', '.join(added)}")
    result.files_modified.append(str(settings_path))
    return result


def uninstall(settings_path: Path) -> GeneratorResult:
    """Remove all prompt-guard hook entries from *settings_path*."""
    result = GeneratorResult(tool_name="prompt-guard")

    if not settings_path.exists():
        result.actions.append("No settings file found — nothing to remove")
        return result

    text = settings_path.read_text()
    try:
        settings: dict = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError:
        result.errors.append(f"Malformed JSON in {settings_path} — fix manually")
        return result

    hooks: dict = settings.get("hooks", {})
    removed: list[str] = []

    for event in list(hooks.keys()):
        before = hooks[event]
        after = [e for e in before if not _entry_has_marker(e)]
        if len(after) < len(before):
            removed.append(event)
            if after:
                hooks[event] = after
            else:
                del hooks[event]

    if not removed:
        result.actions.append("No prompt-guard hooks found — nothing to remove")
        return result

    # Remove the empty "hooks" key entirely if we cleared everything.
    if not hooks:
        del settings["hooks"]

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    result.actions.append(f"Hooks removed: {', '.join(removed)}")
    result.files_modified.append(str(settings_path))
    return result
