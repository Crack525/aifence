"""Hook script — reads a Claude Code hook event from stdin, writes a decision to stdout.

Entry point: aifence-pg-hook  (registered in pyproject.toml console_scripts)

Claude Code invokes this binary synchronously with a 5-second timeout (set in the
hook configuration written by the installer).

Fail-closed design: the hook installs a SIGALRM that fires 1 second before Claude
Code's external kill deadline (4 s internal vs 5 s external). On alarm, the process
exits 2 so Claude Code treats the hook as a blocking error rather than allowing the
action silently. The same exit-2 path is taken on any unhandled exception so a crash
never silently degrades to fail-open.

Note: SIGALRM is POSIX-only (Linux + macOS). On Windows it is unavailable; the
timeout guard is skipped and the hook falls back to fail-open on timeout. Claude
Code for Windows is not yet widely supported so this is an acceptable v1 limitation.
"""

import json
import signal
import sys
from typing import Any

from aifence.prompt_guard.detectors import detect_all, redact

# Internal deadline fires 1 s before Claude Code's 5-s external kill.
_INTERNAL_DEADLINE_SECONDS = 4


def _alarm_handler(signum, frame):  # noqa: ANN001
    """Exit 2 so Claude Code blocks the action rather than failing open."""
    print("aifence-pg-hook: deadline exceeded — blocking as fail-safe", file=sys.stderr)
    sys.exit(2)


def _install_deadline() -> None:
    """Arm the internal deadline if SIGALRM is available (POSIX only)."""
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(_INTERNAL_DEADLINE_SECONDS)

# Tools whose input fields we inspect and potentially redact in PreToolUse.
_TOOL_FIELDS: dict[str, list[str]] = {
    "Bash": ["command", "description"],
    "Write": ["content"],
    "Edit": ["new_string"],
    "WebFetch": ["url"],
    "WebSearch": ["query"],
}


def _detector_summary(detections) -> str:
    """Comma-separated sorted unique detector IDs."""
    return ", ".join(sorted({d.id for d in detections}))


# ---------------------------------------------------------------------------
# Per-event handlers — each returns a JSON-serialisable dict or None (allow).
# ---------------------------------------------------------------------------


def handle_user_prompt_submit(event: dict[str, Any]) -> dict | None:
    """Block prompts that contain detected secrets.

    UserPromptSubmit cannot rewrite the prompt (no updatedInput field on this
    event). The only safe option is to block and ask the user to resubmit after
    removing the secret.
    """
    prompt = event.get("prompt", "")
    detections = detect_all(prompt)
    if not detections:
        return None

    summary = _detector_summary(detections)
    return {
        "decision": "block",
        "reason": (
            f"Sensitive content detected ({summary}). "
            "Remove the secret from your prompt and resubmit."
        ),
    }


def handle_pre_tool_use(event: dict[str, Any]) -> dict | None:
    """Redact secrets from tool input before execution.

    PreToolUse supports updatedInput, so we can replace secret values with
    [REDACTED:<id>] placeholders and allow the tool to proceed.
    """
    tool_name = event.get("tool_name", "")
    tool_input: dict[str, Any] = event.get("tool_input", {})

    # MultiEdit has a list of edits rather than a flat string field.
    if tool_name == "MultiEdit":
        edits = tool_input.get("edits", [])
        if not isinstance(edits, list):
            return None
        redacted_edits = list(edits)
        any_redacted = False
        for i, edit in enumerate(edits):
            if not isinstance(edit, dict):
                continue
            new_str = edit.get("new_string", "")
            if isinstance(new_str, str):
                redacted_value, detections = redact(new_str)
                if detections:
                    redacted_edits[i] = {**edit, "new_string": redacted_value}
                    any_redacted = True
        if not any_redacted:
            return None
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "updatedInput": {**tool_input, "edits": redacted_edits},
            }
        }

    fields = _TOOL_FIELDS.get(tool_name)
    if not fields:
        return None

    redacted_input = dict(tool_input)
    any_redacted = False

    for field in fields:
        value = tool_input.get(field)
        if isinstance(value, str):
            redacted_value, detections = redact(value)
            if detections:
                redacted_input[field] = redacted_value
                any_redacted = True

    if not any_redacted:
        return None

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": redacted_input,
        }
    }


def handle_post_tool_use(event: dict[str, Any]) -> dict | None:
    """Warn Claude if secrets appear in a tool's response.

    The tool has already executed so we cannot prevent the leak, but we can
    instruct Claude not to repeat the sensitive data in its reply.
    """
    tool_response = event.get("tool_response", {})
    if isinstance(tool_response, str):
        text = tool_response
    elif isinstance(tool_response, dict):
        text = json.dumps(tool_response)
    else:
        return None

    detections = detect_all(text)
    if not detections:
        return None

    summary = _detector_summary(detections)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"WARNING: sensitive content ({summary}) was detected in the tool "
                "output. Do not include this data in your response to the user."
            ),
        }
    }


_HANDLERS = {
    "UserPromptSubmit": handle_user_prompt_submit,
    "PreToolUse": handle_pre_tool_use,
    "PostToolUse": handle_post_tool_use,
}


def main() -> None:
    """Entry point installed as aifence-pg-hook."""
    _install_deadline()

    try:
        raw = sys.stdin.read()
        event: dict[str, Any] = json.loads(raw)
    except (json.JSONDecodeError, OSError, ValueError):
        # Malformed input — fail open so a broken packet never blocks the user
        # (the packet itself is not sensitive; no secret to guard here).
        sys.exit(0)
    except Exception:  # noqa: BLE001
        # Unexpected error reading stdin — fail closed.
        sys.exit(2)

    try:
        event_name = event.get("hook_event_name", "")
        handler = _HANDLERS.get(event_name)
        if handler is not None:
            output = handler(event)
            if output is not None:
                print(json.dumps(output))
    except Exception:  # noqa: BLE001
        # Unexpected error during detection — fail closed to avoid silent bypass.
        print("aifence-pg-hook: unexpected error — blocking as fail-safe", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)
