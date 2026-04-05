"""Generator interface and shared types."""

from dataclasses import dataclass, field


@dataclass
class GeneratorResult:
    tool_name: str
    actions: list[str] = field(default_factory=list)  # ✓ lines
    warnings: list[str] = field(default_factory=list)  # ⚠ lines
    errors: list[str] = field(default_factory=list)  # ✗ lines
    files_modified: list[str] = field(default_factory=list)
