"""Tests for the user-configurable rules system in prompt-guard.

Covers:
  - Custom rules loaded from a TOML config file
  - Disabled built-in detectors
  - Config round-trip (write → read)
  - Graceful handling of invalid patterns
  - CLI rules subcommands (add / remove / disable / enable / list)
"""

import re
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from aifence.prompt_guard.detectors import (
    _BUILTIN_DETECTORS,
    _load_config,
    _write_config,
    detect_all,
    get_detectors,
    redact,
)
from aifence.prompt_guard.cli import prompt_guard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def ids(text: str, config_path: Path) -> set[str]:
    return {d.id for d in detect_all(text, config_path)}


# ---------------------------------------------------------------------------
# get_detectors — custom rules loading
# ---------------------------------------------------------------------------


class TestCustomRulesLoading:
    def test_custom_rule_is_appended_to_active_detectors(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent("""\
            [[rules]]
            id = "vault-token"
            description = "HashiCorp Vault service token"
            pattern = '''hvs\\.[A-Za-z0-9_-]{90,}'''
        """))
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "vault-token" in active_ids

    def test_custom_rule_detects_matching_text(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent("""\
            [[rules]]
            id = "internal-token"
            description = "ACME Corp internal service token"
            pattern = '''ACME-[A-Z0-9]{32}'''
        """))
        token = "ACME-" + "A" * 32
        assert "internal-token" in ids(f"token={token}", cfg)

    def test_custom_rule_does_not_fire_on_non_matching_text(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent("""\
            [[rules]]
            id = "acme-token"
            description = "ACME token"
            pattern = '''ACME-[A-Z0-9]{32}'''
        """))
        assert "acme-token" not in ids("just some normal text", cfg)

    def test_multiple_custom_rules_all_loaded(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent("""\
            [[rules]]
            id = "rule-one"
            description = "Rule one"
            pattern = '''TOKEN_ONE_[A-Z]{10}'''

            [[rules]]
            id = "rule-two"
            description = "Rule two"
            pattern = '''TOKEN_TWO_[A-Z]{10}'''
        """))
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "rule-one" in active_ids
        assert "rule-two" in active_ids

    def test_invalid_regex_in_custom_rule_is_skipped_gracefully(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent("""\
            [[rules]]
            id = "bad-rule"
            description = "This has an invalid regex"
            pattern = '''[unclosed bracket'''

            [[rules]]
            id = "good-rule"
            description = "This one is fine"
            pattern = '''GOOD_[A-Z]{10}'''
        """))
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "bad-rule" not in active_ids  # skipped
        assert "good-rule" in active_ids     # still loaded

    def test_missing_config_file_uses_builtins_only(self, tmp_path):
        nonexistent = tmp_path / "no_such_file.toml"
        detectors = get_detectors(nonexistent)
        builtin_ids = {det_id for det_id, _, _ in _BUILTIN_DETECTORS}
        active_ids = {det_id for det_id, _, _ in detectors}
        assert active_ids == builtin_ids

    def test_rule_with_ignorecase_flag(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent("""\
            [[rules]]
            id = "ci-token"
            description = "Case-insensitive internal CI token"
            pattern = '''ci-secret-[a-z0-9]{20}'''
            flags = ["IGNORECASE"]
        """))
        text = "CI-SECRET-" + "A" * 20
        assert "ci-token" in ids(text, cfg)

    def test_rule_with_missing_id_is_skipped(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent("""\
            [[rules]]
            description = "No id field"
            pattern = '''NOID_[A-Z]{10}'''
        """))
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "" not in active_ids

    def test_rule_with_missing_pattern_is_skipped(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent("""\
            [[rules]]
            id = "no-pattern"
            description = "No pattern field"
        """))
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "no-pattern" not in active_ids


# ---------------------------------------------------------------------------
# get_detectors — disabling built-ins
# ---------------------------------------------------------------------------


class TestDisablingBuiltins:
    def test_disabled_builtin_is_removed_from_active_list(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text('disable = ["jwt-token"]')
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "jwt-token" not in active_ids

    def test_disabled_builtin_does_not_detect(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text('disable = ["jwt-token"]')
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert detect_all(jwt, cfg) == []

    def test_non_disabled_builtins_still_work(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text('disable = ["jwt-token"]')
        assert "aws-access-key" in ids("AKIAIOSFODNN7EXAMPLE", cfg)

    def test_multiple_builtins_disabled(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text('disable = ["jwt-token", "bearer-token"]')
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "jwt-token" not in active_ids
        assert "bearer-token" not in active_ids

    def test_disabling_all_builtins_and_adding_custom(self, tmp_path):
        builtin_ids = [det_id for det_id, _, _ in _BUILTIN_DETECTORS]
        disable_line = ", ".join(f'"{i}"' for i in builtin_ids)
        cfg = tmp_path / "prompt_guard.toml"
        cfg.write_text(textwrap.dedent(f"""\
            disable = [{disable_line}]

            [[rules]]
            id = "only-this"
            description = "Only custom rule active"
            pattern = '''MY_SECRET_[A-Z]{{10}}'''
        """))
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert active_ids == {"only-this"}


# ---------------------------------------------------------------------------
# Config round-trip (_write_config → _load_config)
# ---------------------------------------------------------------------------


class TestConfigRoundTrip:
    def test_write_and_read_custom_rule(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        config = {
            "rules": [
                {
                    "id": "my-rule",
                    "description": "My rule",
                    "pattern": r"MY_TOKEN_[A-Z]{20}",
                }
            ]
        }
        _write_config(config, cfg)
        loaded = _load_config(cfg)
        assert loaded["rules"][0]["id"] == "my-rule"
        assert loaded["rules"][0]["pattern"] == r"MY_TOKEN_[A-Z]{20}"

    def test_write_and_read_disabled_ids(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        _write_config({"disable": ["jwt-token", "bearer-token"]}, cfg)
        loaded = _load_config(cfg)
        assert set(loaded["disable"]) == {"jwt-token", "bearer-token"}

    def test_write_preserves_regex_backslashes(self, tmp_path):
        cfg = tmp_path / "prompt_guard.toml"
        pattern = r"hvs\.[A-Za-z0-9_-]{90,}"
        _write_config({"rules": [{"id": "vault", "description": "Vault", "pattern": pattern}]}, cfg)
        loaded = _load_config(cfg)
        assert loaded["rules"][0]["pattern"] == pattern
        # Confirm the loaded pattern actually compiles correctly.
        re.compile(loaded["rules"][0]["pattern"])

    def test_write_escapes_double_quotes_in_description(self, tmp_path):
        """Descriptions with double quotes must not break TOML serialization."""
        cfg = tmp_path / "prompt_guard.toml"
        desc = 'Company "Corp" internal key'
        _write_config({"rules": [{"id": "x", "description": desc, "pattern": "ABC"}]}, cfg)
        loaded = _load_config(cfg)
        assert loaded["rules"][0]["description"] == desc

    def test_write_escapes_triple_quote_in_pattern(self, tmp_path):
        """Patterns containing ''' must not break TOML serialization."""
        cfg = tmp_path / "prompt_guard.toml"
        pattern = "abc'''def"
        _write_config({"rules": [{"id": "y", "description": "test", "pattern": pattern}]}, cfg)
        loaded = _load_config(cfg)
        assert loaded["rules"][0]["pattern"] == pattern
        re.compile(loaded["rules"][0]["pattern"])

    def test_write_escapes_backslash_in_id(self, tmp_path):
        """IDs with backslashes (unusual but shouldn't corrupt the file)."""
        cfg = tmp_path / "prompt_guard.toml"
        _write_config({"rules": [{"id": r"back\slash", "description": "test", "pattern": "ABC"}]}, cfg)
        loaded = _load_config(cfg)
        assert loaded["rules"][0]["id"] == r"back\slash"

    def test_write_creates_parent_directory(self, tmp_path):
        cfg = tmp_path / "nested" / "dir" / "prompt_guard.toml"
        _write_config({"rules": []}, cfg)
        assert cfg.exists()

    def test_write_is_atomic_on_posix(self, tmp_path):
        """Temp file must not persist after write."""
        cfg = tmp_path / "prompt_guard.toml"
        _write_config({"rules": []}, cfg)
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []


# ---------------------------------------------------------------------------
# CLI rules subcommands
# ---------------------------------------------------------------------------


class TestRulesCLI:
    def _runner(self):
        return CliRunner()

    def test_rules_list_shows_all_builtin_detectors(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "aifence.prompt_guard.detectors.DEFAULT_CONFIG_PATH", tmp_path / "prompt_guard.toml"
        )
        monkeypatch.setattr(
            "aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", tmp_path / "prompt_guard.toml"
        )
        result = self._runner().invoke(prompt_guard, ["rules", "list"])
        assert result.exit_code == 0
        assert "aws-access-key" in result.output
        assert "github-token" in result.output

    def test_rules_add_creates_config_and_detects(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        result = self._runner().invoke(prompt_guard, [
            "rules", "add",
            "--id", "acme-key",
            "--description", "ACME Corp API key",
            "--pattern", r"ACME_KEY_[A-Z0-9]{20}",
        ])
        assert result.exit_code == 0, result.output
        assert "acme-key" in result.output

        # Confirm the rule is written and works.
        assert "acme-key" in ids("ACME_KEY_" + "A" * 20, cfg)

    def test_rules_add_duplicate_id_raises_error(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        self._runner().invoke(prompt_guard, [
            "rules", "add", "--id", "my-rule", "--description", "d", "--pattern", r"X{5}",
        ])
        result = self._runner().invoke(prompt_guard, [
            "rules", "add", "--id", "my-rule", "--description", "d", "--pattern", r"Y{5}",
        ])
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_rules_add_builtin_id_raises_error(self, tmp_path, monkeypatch):
        """Adding a custom rule with a built-in ID must be rejected to prevent double-detection."""
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        result = self._runner().invoke(prompt_guard, [
            "rules", "add", "--id", "aws-access-key", "--description", "my override",
            "--pattern", r"AKIA[0-9A-Z]{16}",
        ])
        assert result.exit_code != 0
        assert "built-in" in result.output

    def test_rules_add_invalid_regex_raises_error(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        result = self._runner().invoke(prompt_guard, [
            "rules", "add", "--id", "bad", "--description", "Bad", "--pattern", "[unclosed",
        ])
        assert result.exit_code != 0

    def test_rules_remove_deletes_custom_rule(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        self._runner().invoke(prompt_guard, [
            "rules", "add", "--id", "to-remove", "--description", "d", "--pattern", r"X{5}",
        ])
        result = self._runner().invoke(prompt_guard, ["rules", "remove", "--id", "to-remove"])
        assert result.exit_code == 0
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "to-remove" not in active_ids

    def test_rules_remove_nonexistent_id_raises_error(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        result = self._runner().invoke(prompt_guard, ["rules", "remove", "--id", "ghost"])
        assert result.exit_code != 0

    def test_rules_disable_removes_builtin(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        result = self._runner().invoke(prompt_guard, ["rules", "disable", "--id", "jwt-token"])
        assert result.exit_code == 0
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "jwt-token" not in active_ids

    def test_rules_disable_nonexistent_id_raises_error(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        result = self._runner().invoke(prompt_guard, ["rules", "disable", "--id", "not-a-builtin"])
        assert result.exit_code != 0

    def test_rules_enable_restores_builtin(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        self._runner().invoke(prompt_guard, ["rules", "disable", "--id", "jwt-token"])
        result = self._runner().invoke(prompt_guard, ["rules", "enable", "--id", "jwt-token"])
        assert result.exit_code == 0
        active_ids = {det_id for det_id, _, _ in get_detectors(cfg)}
        assert "jwt-token" in active_ids

    def test_rules_enable_already_active_is_idempotent(self, tmp_path, monkeypatch):
        cfg = tmp_path / "prompt_guard.toml"
        monkeypatch.setattr("aifence.prompt_guard.cli.DEFAULT_CONFIG_PATH", cfg)
        result = self._runner().invoke(prompt_guard, ["rules", "enable", "--id", "jwt-token"])
        assert result.exit_code == 0  # warning, not error
