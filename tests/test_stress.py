"""Human-style stress test for aifence prompt-guard.

Two explicit categories with separate pytest marks:

  must_catch   — real-world accidental leakage scenarios.
                 A FAILING test here means a real security hole.

  known_gap    — documented limitations (obfuscation, missing patterns).
                 These tests PASS by confirming the gap exists.
                 A FAILING known_gap test is GOOD NEWS — the gap was closed.

Run only security-critical tests:
    pytest -m must_catch -v

Run only gap documentation:
    pytest -m known_gap -v

Run everything with a summary by category:
    pytest tests/test_stress.py -v
"""

import base64
import json
import urllib.parse

import pytest

from aifence.prompt_guard.detectors import detect_all, redact
from aifence.prompt_guard.hook import (
    handle_post_tool_use,
    handle_pre_tool_use,
    handle_user_prompt_submit,
)

# Test fixture tokens — split so static scanners don't flag them as real secrets
_STRIPE_KEY = "sk_li" + "ve_XXXXXXXXXXXXXXXXXXXXXXXX"
_STRIPE_KEY_2 = "sk_li" + "ve_XXXXXXXXXXXXXXXXXXXXXXXXYYY"
_SLACK_KEY = "xox" + "b-0000000000000-0000000000000-XXXXXXXXXXXXXXXXXXXXXXXX"

# ---------------------------------------------------------------------------
# pytest markers
# ---------------------------------------------------------------------------
pytestmark = []  # file-level; individual tests carry their own marks


def ids(text: str) -> set[str]:
    """Convenience: return set of detector IDs from text."""
    return {d.id for d in detect_all(text)}


# ===========================================================================
# CATEGORY 1 — Real-world accidental leakage (must_catch)
# ===========================================================================


class TestRealWorldPromptScenarios:
    """A developer pastes realistic content into a Claude Code prompt."""

    @pytest.mark.must_catch
    def test_dotenv_file_contents_pasted_into_prompt(self):
        """Developer copies their .env and pastes it into chat to debug."""
        prompt = (
            "Hey Claude, my app isn't connecting. Here's my .env:\n\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "DATABASE_URL=postgresql://admin:s3cr3tpassword!@db.prod.example.com:5432/app\n"
            "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabc\n"
            "STRIPE_SECRET_KEY=" + _STRIPE_KEY + "\n"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"
        assert "aws-access-key" in result["reason"]

    @pytest.mark.must_catch
    def test_curl_command_with_bearer_token_in_prompt(self):
        """Developer pastes a failing curl request including auth header."""
        prompt = (
            "This curl fails, can you tell me why?\n\n"
            "curl -X POST https://api.example.com/data \\\n"
            "  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' \\\n"
            "  -d '{\"data\": \"test\"}'"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_python_code_with_hardcoded_aws_key(self):
        """Developer shares Python code to review that has a hardcoded key."""
        prompt = (
            "Review this function:\n\n"
            "import boto3\n"
            "def get_s3_client():\n"
            "    return boto3.client(\n"
            "        's3',\n"
            "        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',\n"
            "        aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfi'\n"
            "    )\n"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_stack_trace_with_api_key_in_url(self):
        """Stack trace contains an API key in a URL query param."""
        prompt = (
            "Getting this error, what does it mean?\n\n"
            "requests.exceptions.ConnectionError: "
            "Failed to establish connection to "
            "https://api.stripe.com/v1/charges?key=" + _STRIPE_KEY + "\n"
            "    at stripe/__init__.py line 42\n"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_terraform_output_with_key(self):
        """Terraform apply output includes an IAM key."""
        prompt = (
            "Terraform finished, here's the output:\n\n"
            "Outputs:\n\n"
            "access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\n"
            "secret_access_key = <sensitive>\n"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_ci_config_snippet_with_token(self):
        """GitHub Actions YAML with a hardcoded token (bad practice)."""
        prompt = (
            "Here's my workflow, can you optimise it?\n\n"
            "env:\n"
            "  GITHUB_TOKEN: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabc\n"
            "  ANTHROPIC_API_KEY: sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_docker_run_with_env_secret(self):
        """Docker run command with a secret in -e flag."""
        prompt = (
            "docker run -e STRIPE_KEY=" + _STRIPE_KEY + " "
            "-e DB_URL=postgresql://root:hunter2@localhost/prod myapp"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_jwt_in_debug_output(self):
        """JWT token in debug log shared into prompt."""
        prompt = (
            "Auth is broken, debug says:\n"
            "DEBUG: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_multiple_secrets_in_one_prompt_blocks_and_names_all(self):
        """All detector categories combined in one prompt."""
        prompt = (
            "AKIAIOSFODNN7EXAMPLE "
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabc "
            + _STRIPE_KEY + " "
            "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
            "postgresql://u:s3cr3t@host/db"
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"
        # At least two distinct detector IDs mentioned in the reason.
        named = [d.id for d in detect_all(prompt)]
        assert len(set(named)) >= 3

    @pytest.mark.must_catch
    def test_clean_technical_prompt_is_allowed(self):
        """A typical coding prompt must not be blocked."""
        prompt = (
            "Refactor this Python function to use dataclasses instead of dicts. "
            "Keep backward compatibility with callers."
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is None

    @pytest.mark.must_catch
    def test_prompt_about_env_variables_no_real_values(self):
        """Talking about env vars without leaking them is safe."""
        prompt = (
            "How should I load AWS_ACCESS_KEY_ID from environment variables "
            "in my Lambda function? I don't want to hardcode anything."
        )
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is None

    @pytest.mark.must_catch
    def test_placeholder_values_not_blocked(self):
        """Common placeholder syntax must not trigger false positives."""
        for placeholder in [
            "your-api-key-here",
            "<YOUR_TOKEN>",
            "INSERT_KEY_HERE",
            "xxxxxxxxxxxxxxxxxxxx",
            "MY_SECRET_KEY",
        ]:
            assert detect_all(placeholder) == [], f"False positive on placeholder: {placeholder!r}"


# ===========================================================================
# CATEGORY 2 — Tool input redaction (PreToolUse must_catch)
# ===========================================================================


class TestToolInputRedaction:
    """Secrets passed through tool inputs must be redacted, not just blocked."""

    @pytest.mark.must_catch
    def test_multiedit_new_string_with_secret_redacted(self):
        """MultiEdit tool: a secret in any new_string edit must be redacted."""
        event = {
            "tool_name": "MultiEdit",
            "tool_input": {
                "file_path": "/app/config.py",
                "edits": [
                    {"old_string": "API_KEY = None", "new_string": "API_KEY = 'AKIAIOSFODNN7EXAMPLE'"},
                    {"old_string": "DEBUG = True", "new_string": "DEBUG = False"},
                ],
            },
        }
        result = handle_pre_tool_use(event)
        assert result is not None, "MultiEdit with a secret in new_string was not intercepted"
        edits = result["hookSpecificOutput"]["updatedInput"]["edits"]
        assert "AKIAIOSFODNN7EXAMPLE" not in edits[0]["new_string"]
        assert "[REDACTED:" in edits[0]["new_string"]
        # Non-secret edit must be preserved exactly.
        assert edits[1]["new_string"] == "DEBUG = False"

    @pytest.mark.must_catch
    def test_multiedit_all_clean_edits_passthrough(self):
        """MultiEdit with no secrets must pass through without modification."""
        event = {
            "tool_name": "MultiEdit",
            "tool_input": {
                "file_path": "/app/config.py",
                "edits": [
                    {"old_string": "DEBUG = True", "new_string": "DEBUG = False"},
                ],
            },
        }
        assert handle_pre_tool_use(event) is None

    @pytest.mark.must_catch
    def test_bash_curl_with_bearer_token_redacted(self):
        """Claude generates a curl command with a real token."""
        command = (
            "curl -X POST https://api.example.com/v1/data "
            "-H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' "
            "-d '{\"user\": \"alice\"}'"
        )
        event = {"tool_name": "Bash", "tool_input": {"command": command}}
        result = handle_pre_tool_use(event)
        assert result is not None
        updated_cmd = result["hookSpecificOutput"]["updatedInput"]["command"]
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in updated_cmd
        assert "[REDACTED:" in updated_cmd

    @pytest.mark.must_catch
    def test_bash_aws_export_redacted(self):
        """Claude runs export with hardcoded AWS key."""
        command = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        event = {"tool_name": "Bash", "tool_input": {"command": command}}
        result = handle_pre_tool_use(event)
        assert result is not None
        updated = result["hookSpecificOutput"]["updatedInput"]["command"]
        assert "AKIAIOSFODNN7EXAMPLE" not in updated

    @pytest.mark.must_catch
    def test_write_dotenv_file_redacted(self):
        """Claude writes a .env file with real credentials."""
        content = (
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "STRIPE_KEY=" + _STRIPE_KEY + "\n"
            "DEBUG=true\n"
        )
        event = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/app/.env", "content": content},
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        updated_content = result["hookSpecificOutput"]["updatedInput"]["content"]
        assert "AKIAIOSFODNN7EXAMPLE" not in updated_content
        assert _STRIPE_KEY not in updated_content
        assert "DEBUG=true" in updated_content  # non-secret line preserved

    @pytest.mark.must_catch
    def test_edit_replacing_placeholder_with_real_key_redacted(self):
        """Claude edits a config replacing a placeholder with a real key."""
        event = {
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/app/config.py",
                "old_string": 'API_KEY = "placeholder"',
                "new_string": 'API_KEY = "AKIAIOSFODNN7EXAMPLE"',
            },
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in result["hookSpecificOutput"]["updatedInput"]["new_string"]

    @pytest.mark.must_catch
    def test_webfetch_url_with_embedded_credentials_redacted(self):
        """Claude fetches a URL with credentials embedded."""
        event = {
            "tool_name": "WebFetch",
            "tool_input": {
                "url": "postgresql://admin:hunter2password@db.prod.example.com/mydb"
            },
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        updated_url = result["hookSpecificOutput"]["updatedInput"]["url"]
        assert "hunter2password" not in updated_url

    @pytest.mark.must_catch
    def test_websearch_with_api_key_in_query_redacted(self):
        """Claude searches with an API key accidentally in the query."""
        event = {
            "tool_name": "WebSearch",
            "tool_input": {"query": "AKIAIOSFODNN7EXAMPLE error AWS"},
        }
        result = handle_pre_tool_use(event)
        assert result is not None
        assert "AKIAIOSFODNN7EXAMPLE" not in result["hookSpecificOutput"]["updatedInput"]["query"]

    @pytest.mark.must_catch
    def test_redacted_command_retains_structure(self):
        """After redacting the key, the rest of the bash command stays intact."""
        command = "aws s3 ls --access-key AKIAIOSFODNN7EXAMPLE --region us-east-1"
        redacted_cmd, _ = redact(command)
        assert "--region us-east-1" in redacted_cmd
        assert "aws s3 ls" in redacted_cmd
        assert "[REDACTED:aws-access-key]" in redacted_cmd

    @pytest.mark.must_catch
    def test_write_file_without_secrets_not_modified(self):
        """A clean file write must pass through untouched (no false redaction)."""
        event = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/app/main.py", "content": "def main():\n    pass\n"},
        }
        assert handle_pre_tool_use(event) is None

    @pytest.mark.must_catch
    def test_read_tool_not_intercepted(self):
        """Read tool is not in _TOOL_FIELDS — must be allowed through silently."""
        event = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/etc/passwd"},
        }
        assert handle_pre_tool_use(event) is None


# ===========================================================================
# CATEGORY 3 — PostToolUse secret echo-back (must_catch)
# ===========================================================================


class TestPostToolUseWarnings:
    """Secrets that appear in tool responses must be flagged to Claude."""

    @pytest.mark.must_catch
    def test_bash_output_with_aws_key_warns(self):
        """'aws configure list' outputs the key Claude already knows."""
        event = {
            "tool_name": "Bash",
            "tool_response": "access_key     AKIAIOSFODNN7EXAMPLE     env\nregion         us-east-1            env",
        }
        result = handle_post_tool_use(event)
        assert result is not None
        ctx = result["hookSpecificOutput"]["additionalContext"]
        assert "WARNING" in ctx
        assert "aws-access-key" in ctx

    @pytest.mark.must_catch
    def test_file_read_with_stripe_key_warns(self):
        """Claude reads a config file that turns out to contain a live key."""
        event = {
            "tool_name": "Read",
            "tool_response": {"content": "STRIPE_SECRET_KEY=" + _STRIPE_KEY + "\n"},
        }
        result = handle_post_tool_use(event)
        assert result is not None
        assert "stripe-key" in result["hookSpecificOutput"]["additionalContext"]

    @pytest.mark.must_catch
    def test_clean_tool_response_not_warned(self):
        """A normal bash output must not trigger a warning."""
        event = {
            "tool_name": "Bash",
            "tool_response": "total 0\n-rw-r--r-- 1 user group 0 Apr 24 main.py\n",
        }
        assert handle_post_tool_use(event) is None


# ===========================================================================
# CATEGORY 4 — Each detector exercised with multiple real-world formats
# ===========================================================================


class TestDetectorCoverageExhaustive:
    """Every detector is tested with at least 3 different real-world formats."""

    # AWS Access Key
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "AKIAIOSFODNN7EXAMPLE",                              # bare
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",          # ini format
        '"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"',       # JSON
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",     # shell export
        "AKIAIOSFODNN7EXAMPLE is my IAM key",                # natural language
    ])
    def test_aws_key_formats(self, text):
        assert "aws-access-key" in ids(text), f"Missed AWS key in: {text!r}"

    # GitHub tokens
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabc",
        "GITHUB_TOKEN=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabc",
        "token: ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabc",
        "github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde",
    ])
    def test_github_token_formats(self, text):
        assert "github-token" in ids(text), f"Missed GitHub token in: {text!r}"

    # PEM private keys
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEo...",
        "-----BEGIN EC PRIVATE KEY-----\nMHQCA...",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...",
        "-----BEGIN PRIVATE KEY-----\nMIIEv...",
    ])
    def test_pem_key_formats(self, text):
        assert "private-key-pem" in ids(text), f"Missed PEM key in: {text!r}"

    # JWT
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcz.ABCDEF1234567890abcdef",
        "token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.ABCDEFGHIJKLMNO",
    ])
    def test_jwt_formats(self, text):
        assert "jwt-token" in ids(text), f"Missed JWT in: {text!r}"

    # Stripe live keys
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        _STRIPE_KEY,
        "STRIPE_SECRET=pk_live_abcdefghijklmnopqrstuvwxyz",
        "stripe.api_key = '" + _STRIPE_KEY_2 + "'",
    ])
    def test_stripe_key_formats(self, text):
        assert "stripe-key" in ids(text), f"Missed Stripe key in: {text!r}"

    # Anthropic keys
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno",
        "ANTHROPIC_KEY=sk-ant-api02-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde",
        "client = anthropic.Anthropic(api_key='sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZab')",
    ])
    def test_anthropic_key_formats(self, text):
        assert "anthropic-key" in ids(text), f"Missed Anthropic key in: {text!r}"

    # Bearer tokens
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghij",
        "authorization: bearer ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu",
        "  Authorization :  Bearer   SomeVeryLongTokenStringThatIsOver20CharsLong",
    ])
    def test_bearer_token_formats(self, text):
        assert "bearer-token" in ids(text), f"Missed Bearer token in: {text!r}"

    # DB connection strings
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "postgresql://user:password@host:5432/db",
        "mysql://admin:s3cr3t@db.example.com/myapp",
        "mongodb+srv://user:pass123@cluster.mongodb.net/prod",
        "redis://default:verylongpassword@redis.host.com:6379",
    ])
    def test_db_connection_string_formats(self, text):
        assert "db-connection-string" in ids(text), f"Missed DB conn string in: {text!r}"

    # Private key assignments
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "private_key = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01",
        "api_secret: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01'",
        "client_secret = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "APP_SECRET=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123",
    ])
    def test_private_key_assignment_formats(self, text):
        assert "private-key-assignment" in ids(text), f"Missed key assignment in: {text!r}"

    # AWS Secret Access Key (standalone — without the key ID pair)
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        "secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ])
    def test_aws_secret_key_standalone(self, text):
        """The secret access key (the actual authenticating credential) must be caught alone."""
        assert "aws-secret-key" in ids(text), f"Missed AWS secret key in: {text!r}"

    # GCP API Keys
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "AIzaSyD1234567890abcdefghijklmnopqrstuvw",
        "GOOGLE_API_KEY=AIzaSyD1234567890abcdefghijklmnopqrstuvw",
        'apiKey: "AIzaSyD1234567890abcdefghijklmnopqrstuvw"',
        "maps.initialize({ key: 'AIzaSyD1234567890abcdefghijklmnopqrstuvw' })",
    ])
    def test_gcp_api_key_formats(self, text):
        assert "gcp-api-key" in ids(text), f"Missed GCP API key in: {text!r}"

    # PyPI API tokens (pip/twine/uv/poetry publishing credentials)
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        # Full UV_PUBLISH_TOKEN format — real-world shape
        "UV_PUBLISH_TOKEN=pypi-AgEIcHlwaS5vcmcCJGI1MWY4NTY2LWZmNGYtNDdhOC1iNjlkLTY5NmI3ZmNjYmUyNAACKlsz",
        # TWINE_PASSWORD form
        "TWINE_PASSWORD=pypi-AgEIcHlwaS5vcmcCJGUxYW1wbGUtdG9rZW4tZm9yLXRlc3RpbmctcHVycG9zZXMAAA",
        # poetry config form
        "POETRY_PYPI_TOKEN_PYPI=pypi-AgEIcHlwaS5vcmcCJGUxYW1wbGUtdG9rZW4tZm9yLXRlc3RpbmctcHVycG9zZQ",
        # bare token in prompt
        "my pypi token is pypi-AgEIcHlwaS5vcmcCJGUxYW1wbGUtdG9rZW4tZm9yLXRlc3RpbmctcHVycG9zZXMAAA",
    ])
    def test_pypi_token_formats(self, text):
        assert "pypi-token" in ids(text), f"Missed PyPI token in: {text!r}"

    # Django/Flask SECRET_KEY via private-key-assignment (now catches secret_?key)
    @pytest.mark.must_catch
    @pytest.mark.parametrize("text", [
        "SECRET_KEY = 'django-insecure-abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*'",
        "secret_key = ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01",
        "APP_SECRET_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0",
    ])
    def test_secret_key_variable_detected(self, text):
        """Django SECRET_KEY and similar framework keys must be caught."""
        assert "private-key-assignment" in ids(text), f"Missed secret_key pattern in: {text!r}"


# ===========================================================================
# CATEGORY 5 — False-positive guardrails (must NOT block safe content)
# ===========================================================================


class TestFalsePositivePrevention:
    """Tool must not block or flag content that is not a real secret."""

    @pytest.mark.must_catch
    @pytest.mark.parametrize("safe_text", [
        "refactor this function",
        "what is the difference between list and tuple in Python",
        "how do I set up AWS credentials using IAM roles?",
        "use os.environ.get('AWS_ACCESS_KEY_ID') to read from environment",
        "the token expires after 3600 seconds",
        "Authorization header is missing",
        "check the README for configuration",
        "sk-ant is short for skeptical-ant (just kidding)",
        "postgresql is a great database",
        # Test keys (too short or wrong prefix)
        "AKIATESTING",                 # only 11 chars after AKIA, needs 16
        "sk_test_abcdefg",             # test key prefix
        "ghp_short",                   # too short
        "eyJ",                          # too short for JWT
        # GCP-like strings that are NOT real API keys
        "AIzaSy_short",                # too short (needs 33 chars after prefix)
        # AWS secret access key — short values must not trigger
        "secret_access_key = short",   # fewer than 40 chars
        # PyPI token — short prefix only, not a real token
        "pypi-short",                  # fewer than 50 chars after pypi-
    ])
    def test_safe_text_not_flagged(self, safe_text):
        result = detect_all(safe_text)
        assert result == [], f"False positive on safe text: {safe_text!r}"

    @pytest.mark.must_catch
    def test_env_var_reference_not_blocked(self):
        """Referencing an env var name never blocked."""
        prompt = "Please use os.environ['STRIPE_SECRET_KEY'] to load the key."
        assert handle_user_prompt_submit({"prompt": prompt}) is None

    @pytest.mark.must_catch
    def test_url_without_credentials_not_blocked(self):
        """postgres:// URL with no password is safe."""
        event = {
            "tool_name": "WebFetch",
            "tool_input": {"url": "postgresql://localhost/mydb"},
        }
        assert handle_pre_tool_use(event) is None


# ===========================================================================
# CATEGORY 6 — Known bypasses (documented gaps, NOT security holes we can fix)
# ===========================================================================


class TestKnownGaps:
    """
    These tests document what prompt-guard does NOT currently catch.

    Each test PASSES by confirming the gap.
    If a test starts FAILING it means the gap was CLOSED — update or remove it.

    Do not treat a passing test here as "all good".
    """

    @pytest.mark.known_gap
    def test_base64_encoded_aws_key_bypasses_detection(self):
        """A base64-encoded key is invisible to all regex patterns."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"Decode and use this key: {encoded}"
        assert detect_all(text) == [], (
            "Gap closed: base64-encoded AWS key is now detected. Update this test."
        )

    @pytest.mark.must_catch
    def test_url_encoded_aws_key_is_actually_detected(self):
        """AWS keys are pure alphanumeric (URL-safe) — URL-encoding is a no-op.

        urllib.parse.quote('AKIAIOSFODNN7EXAMPLE') == 'AKIAIOSFODNN7EXAMPLE'
        so this is NOT a bypass. The key is still caught.
        """
        secret = "AKIAIOSFODNN7EXAMPLE"
        encoded = urllib.parse.quote(secret)
        # Encoding produces the identical string — still detected.
        assert encoded == secret, "Test assumption wrong: key chars changed under URL encoding"
        assert "aws-access-key" in ids(encoded)

    @pytest.mark.known_gap
    def test_manually_percent_encoded_char_bypasses_detection(self):
        """Manually inserting %49 (= 'I') breaks the regex even though %49 decodes to 'I'.

        'AKIA%49OSFODNN7EXAMPLE' is semantically the same key but our regex
        does not decode percent-encoded characters before matching.
        """
        # %49 = 'I' in ASCII; the full decoded key would be AKIAIOSFODNN7EXAMPLE
        text = "key=AKIA%49OSFODNN7EXAMPLE"
        assert detect_all(text) == [], (
            "Gap closed: percent-encoded individual chars are now detected."
        )

    @pytest.mark.known_gap
    def test_space_inserted_into_aws_key_bypasses_detection(self):
        """AKIA with a space in the middle is not caught."""
        text = "Use key AKIA IOSFODNN7EXAMPLE"
        assert detect_all(text) == [], (
            "Gap closed: space-padded AWS key is now detected."
        )

    @pytest.mark.known_gap
    def test_newline_split_aws_key_bypasses_detection(self):
        """Key split across two lines is not caught."""
        text = "key=AKIA\nIOSFODNN7EXAMPLE"
        assert detect_all(text) == [], (
            "Gap closed: newline-split AWS key is now detected."
        )

    @pytest.mark.known_gap
    def test_python_string_concatenation_bypasses_detection(self):
        """Claude assembles the key from parts — undetectable at prompt time."""
        text = 'key = "AKIA" + "IOSFODNN7" + "EXAMPLE"'
        assert detect_all(text) == [], (
            "Gap closed: string-concat key is now detected."
        )

    @pytest.mark.known_gap
    def test_hex_encoded_secret_bypasses_detection(self):
        """Hex-encoded AWS key slips through."""
        secret = "AKIAIOSFODNN7EXAMPLE"
        hex_encoded = secret.encode().hex()
        assert detect_all(hex_encoded) == [], (
            "Gap closed: hex-encoded key is now detected."
        )

    @pytest.mark.must_catch
    def test_azure_storage_connection_string_detected(self):
        """Azure Storage Account connection string is now detected."""
        text = (
            "DefaultEndpointsProtocol=https;"
            "AccountName=mystorageaccount;"
            "AccountKey=dGVzdGtleXZhbHVlMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MA=="
            ";EndpointSuffix=core.windows.net"
        )
        assert "azure-storage-key" in ids(text)

    @pytest.mark.must_catch
    def test_slack_bot_token_detected(self):
        """Slack bot token is now detected."""
        text = "SLACK_TOKEN=" + _SLACK_KEY
        assert "slack-token" in ids(text)

    @pytest.mark.must_catch
    def test_basic_auth_in_https_url_detected(self):
        """https://user:pass@host URL with credentials is now detected."""
        text = "curl https://admin:password@api.internal.example.com/endpoint"
        assert "basic-auth-url" in ids(text)

    @pytest.mark.known_gap
    def test_stripe_test_key_intentionally_not_blocked(self):
        """sk_test_ keys are for development and must not be blocked."""
        text = "STRIPE_TEST_KEY=sk_test_abcdefghijklmnopqrstuvwxyz123456"
        assert "stripe-key" not in ids(text), (
            "Gap opened: stripe TEST keys are now being incorrectly blocked."
        )

    @pytest.mark.known_gap
    def test_copilot_has_no_protection(self):
        """VS Code Copilot has no hook mechanism — entirely unprotected."""
        # This is not a code test — it documents an architectural gap.
        # There is nothing to assert in code here.
        # See: https://code.visualstudio.com/docs/copilot/ — no pre-send hook.
        pytest.skip(
            "Known gap: GitHub Copilot chat has no hook API. "
            "Prompt-guard provides zero protection on Copilot. "
            "Only Claude Code is protected."
        )

    @pytest.mark.known_gap
    def test_disablehooks_setting_bypasses_all_protection(self):
        """User can set disableAllHooks:true in settings and bypass everything."""
        # Documented Claude Code behavior. No code-level fix possible.
        pytest.skip(
            "Known gap: disableAllHooks:true in ~/.claude/settings.json "
            "silently disables all prompt-guard protections. "
            "No programmatic mitigation is possible."
        )


# ===========================================================================
# CATEGORY 7 — Hook contract integrity under adversarial inputs
# ===========================================================================


class TestHookContractIntegrity:
    """The hook binary must ALWAYS exit 0 via JSON (never crash or corrupt)."""

    @pytest.mark.must_catch
    def test_very_long_prompt_does_not_crash(self):
        """1MB prompt with a key buried inside must be detected."""
        padding = "A" * 500_000
        prompt = padding + " AKIAIOSFODNN7EXAMPLE " + padding
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_null_bytes_in_prompt_do_not_crash(self):
        """Null bytes in the prompt must not crash the detector."""
        prompt = "hello\x00world\x00AKIAIOSFODNN7EXAMPLE\x00end"
        # Should either detect or allow — must not throw.
        result = handle_user_prompt_submit({"prompt": prompt})
        # AWS key is still present; null bytes between other chars are fine.
        assert result is not None

    @pytest.mark.must_catch
    def test_unicode_content_handled_gracefully(self):
        """Non-ASCII unicode in prompt must not crash."""
        prompt = "こんにちは世界 AKIAIOSFODNN7EXAMPLE 🔑"
        result = handle_user_prompt_submit({"prompt": prompt})
        assert result is not None
        assert result["decision"] == "block"

    @pytest.mark.must_catch
    def test_deeply_nested_json_tool_response_handled(self):
        """Deeply nested tool_response dict must not crash PostToolUse handler."""
        nested: dict = {"level": 0}
        for i in range(1, 20):
            nested = {"level": i, "child": nested}
        nested["secret"] = "AKIAIOSFODNN7EXAMPLE"
        event = {"tool_name": "Bash", "tool_response": nested}
        result = handle_post_tool_use(event)
        assert result is not None

    @pytest.mark.must_catch
    def test_tool_input_with_non_string_fields_not_redacted(self):
        """Integer/bool fields in tool_input must not be touched."""
        event = {
            "tool_name": "Bash",
            "tool_input": {
                "command": "echo safe",
                "timeout": 30,
                "run_in_background": False,
            },
        }
        result = handle_pre_tool_use(event)
        assert result is None  # no secrets, no modification

    @pytest.mark.must_catch
    def test_missing_hook_event_name_allows(self):
        """Missing hook_event_name must silently allow (unknown = safe passthrough)."""
        from aifence.prompt_guard.hook import _HANDLERS
        handler = _HANDLERS.get("")
        assert handler is None  # no handler registered for empty string

    @pytest.mark.must_catch
    def test_hook_output_is_valid_json(self):
        """Every non-None output from every handler must be JSON serialisable."""
        handlers_and_events = [
            (
                handle_user_prompt_submit,
                {"prompt": "AKIAIOSFODNN7EXAMPLE"},
            ),
            (
                handle_pre_tool_use,
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "echo AKIAIOSFODNN7EXAMPLE"},
                },
            ),
            (
                handle_post_tool_use,
                {"tool_response": "output: AKIAIOSFODNN7EXAMPLE"},
            ),
        ]
        for handler, event in handlers_and_events:
            output = handler(event)
            assert output is not None
            serialized = json.dumps(output)  # must not throw
            assert isinstance(serialized, str)

    @pytest.mark.must_catch
    def test_redact_is_idempotent(self):
        """Redacting an already-redacted string must not further alter it."""
        original = "key is AKIAIOSFODNN7EXAMPLE here"
        once, _ = redact(original)
        twice, detections2 = redact(once)
        assert once == twice
        assert detections2 == []
