"""Prompt content detectors — high-precision regex patterns for common secrets.

Built-in detectors cover the most common secret formats.
Add custom patterns — or disable noisy built-ins — in ~/.aifence/prompt_guard.toml.
No code changes or reinstall required; the hook picks up the file on every run.

Example ~/.aifence/prompt_guard.toml
─────────────────────────────────────
# Disable a built-in that causes false positives in your project
disable = ["jwt-token"]

# Add a company-specific or service-specific secret pattern
[[rules]]
id = "vault-token"
description = "HashiCorp Vault service token"
pattern = '''hvs\\.[A-Za-z0-9_-]{90,}'''

[[rules]]
id = "doppler-token"
description = "Doppler service token"
pattern = '''dp\\.st\\.[A-Za-z0-9_-]{40,}'''
─────────────────────────────────────
Manage rules via CLI: aifence prompt-guard rules --help
"""

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

# Default location for user config — override in tests via config_path args.
DEFAULT_CONFIG_PATH = Path.home() / ".aifence" / "prompt_guard.toml"


@dataclass
class Detection:
    id: str
    description: str
    match_start: int
    match_end: int


def _load_config(config_path: Path) -> dict:
    """Load TOML config, returning empty dict if missing or unreadable."""
    try:
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001
        # Corrupt or unreadable config — fail safe with built-ins only.
        return {}


def _toml_str(value: str) -> str:
    """Return a TOML basic string literal (double-quoted) with proper escaping."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _write_config(config: dict, path: Path) -> None:
    """Serialise config dict back to TOML and write atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []

    disable = sorted(set(config.get("disable", [])))
    if disable:
        items = ", ".join(f'"{d}"' for d in disable)
        lines.append(f"disable = [{items}]")
        lines.append("")

    for rule in config.get("rules", []):
        lines.append("[[rules]]")
        lines.append(f"id = {_toml_str(rule['id'])}")
        lines.append(f"description = {_toml_str(rule['description'])}")
        # Use basic TOML string so backslashes and quotes are safely escaped.
        lines.append(f"pattern = {_toml_str(rule['pattern'])}")
        if rule.get("flags"):
            flags_str = ", ".join(f'"{f}"' for f in rule["flags"])
            lines.append(f"flags = [{flags_str}]")
        lines.append("")

    tmp = path.with_suffix(".toml.tmp")
    tmp.write_text("\n".join(lines), encoding="utf-8")
    tmp.replace(path)  # atomic on POSIX


def get_detectors(
    config_path: Path | None = None,
) -> list[tuple[str, str, re.Pattern]]:
    """Return the active detector list.

    Built-in detectors minus any the user has disabled, followed by
    any custom rules defined in the config file.

    Args:
        config_path: Override the default ~/.aifence/prompt_guard.toml location.
                     Primarily used in tests.
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    config = _load_config(config_path)
    disabled: set[str] = set(config.get("disable", []))

    detectors: list[tuple[str, str, re.Pattern]] = [
        (det_id, desc, pat)
        for det_id, desc, pat in _BUILTIN_DETECTORS
        if det_id not in disabled
    ]

    for rule in config.get("rules", []):
        rule_id = str(rule.get("id", "")).strip()
        description = str(rule.get("description", rule_id))
        pattern_str = str(rule.get("pattern", "")).strip()
        if not rule_id or not pattern_str:
            continue

        flags = 0
        for flag_name in rule.get("flags", []):
            name = str(flag_name).upper()
            if name == "ASCII":
                flags |= re.ASCII
            elif name == "IGNORECASE":
                flags |= re.IGNORECASE
            elif name == "MULTILINE":
                flags |= re.MULTILINE

        try:
            compiled = re.compile(pattern_str, flags)
        except re.error:
            # Skip invalid user patterns — crashing the hook is worse than missing coverage.
            continue

        detectors.append((rule_id, description, compiled))

    return detectors


# Built-in detectors — the default set shipped with aifence.
# Each entry: (id, description, compiled_pattern)
_BUILTIN_DETECTORS: list[tuple[str, str, re.Pattern]] = [
    (
        "aws-access-key",
        "AWS Access Key ID",
        re.compile(r"AKIA[0-9A-Z]{16}", re.ASCII),
    ),
    (
        "github-token",
        "GitHub Personal Access Token",
        re.compile(r"(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{10,}", re.ASCII),
    ),
    (
        "private-key-pem",
        "PEM Private Key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "jwt-token",
        "JSON Web Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
    ),
    (
        "stripe-key",
        "Stripe Live API Key",
        re.compile(r"(?:sk|pk)_live_[0-9A-Za-z]{24,}", re.ASCII),
    ),
    (
        "anthropic-key",
        "Anthropic API Key",
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}", re.ASCII),
    ),
    (
        "openai-key",
        "OpenAI API Key",
        re.compile(r"sk-(?:proj-|T3BlbkFJ)[A-Za-z0-9]{20,}", re.ASCII),
    ),
    (
        "bearer-token",
        "HTTP Authorization Bearer token",
        re.compile(
            r"(?i)Authorization\s*:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}[=]*"
        ),
    ),
    (
        "db-connection-string",
        "Database connection string with embedded credentials",
        re.compile(
            r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:@\s]+:[^@\s]{4,}@\S+"
        ),
    ),
    (
        "private-key-assignment",
        "Private key or secret value in assignment",
        re.compile(
            r"(?i)(?:private_?key|secret_?key|api_?secret|client_?secret|app_?secret)"
            r"\s*[=:]\s*['\"]?[A-Za-z0-9/+=_\-]{32,}['\"]?",
        ),
    ),
    (
        "aws-secret-key",
        "AWS Secret Access Key",
        re.compile(
            r"(?i)(?:aws_)?secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}['\"]?"
        ),
    ),
    (
        "gcp-api-key",
        "Google Cloud Platform API Key",
        re.compile(r"AIzaSy[A-Za-z0-9_-]{33}", re.ASCII),
    ),
    (
        "pypi-token",
        "PyPI API token (used by pip, twine, uv, poetry)",
        re.compile(r"pypi-[A-Za-z0-9_\-+/=]{50,}", re.ASCII),
    ),
    (
        "slack-token",
        "Slack Bot or User OAuth token",
        re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}", re.ASCII),
    ),
    (
        "azure-storage-key",
        "Azure Storage Account connection string",
        re.compile(
            r"(?i)DefaultEndpointsProtocol=https?;"
            r"AccountName=[^;]+;"
            r"AccountKey=[A-Za-z0-9+/]{60,}={0,2}"
        ),
    ),
    (
        "basic-auth-url",
        "HTTP Basic Auth credentials embedded in a URL",
        re.compile(
            r"https?://[A-Za-z0-9._~%-]+:[A-Za-z0-9._~!$&'()*+,;=%-]{4,}@[A-Za-z0-9.-]+"
        ),
    ),
]


def detect_all(text: str, config_path: Path | None = None) -> list[Detection]:
    """Run all active detectors against text. Returns every match found."""
    results: list[Detection] = []
    for det_id, description, pattern in get_detectors(config_path):
        for m in pattern.finditer(text):
            results.append(
                Detection(
                    id=det_id,
                    description=description,
                    match_start=m.start(),
                    match_end=m.end(),
                )
            )
    return results


def redact(text: str, config_path: Path | None = None) -> tuple[str, list[Detection]]:
    """Replace detected secrets with [REDACTED:<id>] placeholders.

    Returns (redacted_text, original_detections).
    Replacements are applied right-to-left to preserve offsets.
    Overlapping matches use the first detector's replacement.
    """
    detections = detect_all(text, config_path)
    if not detections:
        return text, []

    # Sort descending by start so right-to-left replacement keeps offsets valid.
    candidates = sorted(detections, key=lambda d: d.match_start, reverse=True)

    # Deduplicate overlapping ranges — keep leftmost (earliest start) match.
    # Since we iterate right-to-left, "skip if overlaps anything already kept".
    kept: list[Detection] = []
    kept_ranges: list[tuple[int, int]] = []
    for det in candidates:
        overlap = any(
            det.match_start < end and det.match_end > start
            for start, end in kept_ranges
        )
        if not overlap:
            kept.append(det)
            kept_ranges.append((det.match_start, det.match_end))

    result = text
    for det in kept:
        placeholder = f"[REDACTED:{det.id}]"
        result = result[: det.match_start] + placeholder + result[det.match_end :]

    return result, detections
