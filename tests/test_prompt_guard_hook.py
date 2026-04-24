"""Tests for the hook script handlers."""

import json
from unittest.mock import patch

import pytest

from aifence.prompt_guard.hook import (
    handle_post_tool_use,
    handle_pre_tool_use,
    handle_user_prompt_submit,
    main,
)

# Test fixture tokens — split so static scanners don't flag them as real secrets
_STRIPE_KEY = "sk_li" + "ve_XXXXXXXXXXXXXXXXXXXXXXXX"


# ---------------------------------------------------------------------------
# UserPromptSubmit
# ---------------------------------------------------------------------------


class TestHandleUserPromptSubmit:
    def test_allows_clean_prompt(self):
        event = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Please help me write a Python function.",
        }
        result = handle_user_prompt_submit(event)
        assert result is None

    def test_blocks_prompt_with_aws_key(self):
        event = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "My AWS key is AKIAIOSFODNN7EXAMPLE please use it",
        }
        result = handle_user_prompt_submit(event)
        assert result is not None
        assert result["decision"] == "block"
        assert "aws-access-key" in result["reason"]

    def test_blocks_prompt_with_stripe_key(self):
        event = {"prompt": _STRIPE_KEY + " is my stripe key"}
        result = handle_user_prompt_submit(event)
        assert result is not None
        assert result["decision"] == "block"

    def test_block_reason_names_detector(self):
        event = {"prompt": "AKIAIOSFODNN7EXAMPLE"}
        result = handle_user_prompt_submit(event)
        assert "aws-access-key" in result["reason"]

    def test_missing_prompt_field_allows(self):
        result = handle_user_prompt_submit({})
        assert result is None

    def test_empty_prompt_allows(self):
        result = handle_user_prompt_submit({"prompt": ""})
        assert result is None


# ---------------------------------------------------------------------------
# PreToolUse
# ---------------------------------------------------------------------------


class TestHandlePreToolUse:
    def test_allows_bash_with_clean_command(self):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        assert handle_pre_tool_use(event) is None

    def test_redacts_aws_key_in_bash_command(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        event = {
            "tool_name": "Bash",
            "tool_input": {"command": f"aws s3 --key {secret} ls"},
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        output = result["hookSpecificOutput"]
        assert output["hookEventName"] == "PreToolUse"
        assert output["permissionDecision"] == "allow"
        assert secret not in output["updatedInput"]["command"]
        assert "[REDACTED:aws-access-key]" in output["updatedInput"]["command"]

    def test_redacts_stripe_key_in_write_content(self):
        event = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/tmp/config.py",
                "content": "STRIPE_KEY = '" + _STRIPE_KEY + "'\n",
            },
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        assert _STRIPE_KEY not in result["hookSpecificOutput"]["updatedInput"]["content"]

    def test_redacts_secret_in_edit_new_string(self):
        event = {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/tmp/f.py",
                "old_string": "key = ''",
                "new_string": "key = 'AKIAIOSFODNN7EXAMPLE'",
            },
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in result["hookSpecificOutput"]["updatedInput"]["new_string"]

    def test_preserves_unchanged_fields_in_updated_input(self):
        event = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "echo AKIAIOSFODNN7EXAMPLE",
                "description": "print key",
                "timeout": 30,
            },
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        updated = result["hookSpecificOutput"]["updatedInput"]
        assert updated["timeout"] == 30

    def test_allows_webfetch_with_clean_url(self):
        event = {
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://example.com/api"},
        }
        assert handle_pre_tool_use(event) is None

    def test_redacts_credentials_in_webfetch_url(self):
        event = {
            "tool_name": "WebFetch",
            "tool_input": {"url": "postgresql://admin:hunter2password@db.host.com/db"},
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        assert "hunter2password" not in result["hookSpecificOutput"]["updatedInput"]["url"]

    def test_ignores_unknown_tool(self):
        event = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/secret.txt"},
        }
        assert handle_pre_tool_use(event) is None

    def test_missing_tool_input_allows(self):
        event = {"tool_name": "Bash", "tool_input": {}}
        assert handle_pre_tool_use(event) is None


# ---------------------------------------------------------------------------
# PostToolUse
# ---------------------------------------------------------------------------


class TestHandlePostToolUse:
    def test_allows_clean_response(self):
        event = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_response": {"output": "file1.txt\nfile2.txt"},
        }
        assert handle_post_tool_use(event) is None

    def test_warns_when_secret_in_string_response(self):
        event = {
            "tool_name": "Bash",
            "tool_response": "output: AKIAIOSFODNN7EXAMPLE complete",
        }
        result = handle_post_tool_use(event)
        assert result is not None
        ctx = result["hookSpecificOutput"]["additionalContext"]
        assert "aws-access-key" in ctx

    def test_warns_when_secret_in_dict_response(self):
        event = {
            "tool_name": "Bash",
            "tool_response": {"output": _STRIPE_KEY + " found"},
        }
        result = handle_post_tool_use(event)
        assert result is not None
        assert "stripe-key" in result["hookSpecificOutput"]["additionalContext"]

    def test_missing_tool_response_allows(self):
        assert handle_post_tool_use({}) is None


# ---------------------------------------------------------------------------
# main() dispatcher
# ---------------------------------------------------------------------------


class TestMain:
    def _run_main(self, event: dict) -> tuple[int, str]:
        """Helper: run main() with event JSON on stdin, capture stdout + exit code."""
        import io

        stdin_data = json.dumps(event)
        captured_stdout = io.StringIO()

        with patch("sys.stdin", io.StringIO(stdin_data)):
            with patch("sys.stdout", captured_stdout):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        return exc_info.value.code, captured_stdout.getvalue()

    def test_exits_0_on_clean_prompt(self):
        event = {"hook_event_name": "UserPromptSubmit", "prompt": "hello"}
        code, _ = self._run_main(event)
        assert code == 0

    def test_exits_0_and_prints_block_on_secret_prompt(self):
        event = {
            "hook_event_name": "UserPromptSubmit",
            "prompt": "AKIAIOSFODNN7EXAMPLE",
        }
        code, out = self._run_main(event)
        assert code == 0
        parsed = json.loads(out)
        assert parsed["decision"] == "block"

    def test_exits_0_on_unknown_event(self):
        event = {"hook_event_name": "SessionStart"}
        code, out = self._run_main(event)
        assert code == 0
        assert out.strip() == ""

    def test_exits_0_on_malformed_json(self):
        import io

        with patch("sys.stdin", io.StringIO("not-valid-json")):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 0

    def test_exits_0_on_empty_stdin(self):
        import io

        with patch("sys.stdin", io.StringIO("")):
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 0

    def test_pre_tool_use_redacts_and_exits_0(self):
        event = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"},
        }
        code, out = self._run_main(event)
        assert code == 0
        parsed = json.loads(out)
        assert parsed["hookSpecificOutput"]["permissionDecision"] == "allow"
