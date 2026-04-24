"""Tests for prompt-guard content detectors."""

from aifence.prompt_guard.detectors import Detection, detect_all, redact

# Test fixture tokens — split so static scanners don't flag them as real secrets
_STRIPE_KEY = "sk_li" + "ve_XXXXXXXXXXXXXXXXXXXXXXXX"


class TestDetectAll:
    def test_clean_text_returns_empty(self):
        assert detect_all("Hello, world! No secrets here.") == []

    def test_empty_string_returns_empty(self):
        assert detect_all("") == []

    def test_aws_access_key_detected(self):
        text = "Use key AKIAIOSFODNN7EXAMPLE to authenticate"
        results = detect_all(text)
        ids = {d.id for d in results}
        assert "aws-access-key" in ids

    def test_github_token_ghp_detected(self):
        text = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabc"
        results = detect_all(text)
        assert any(d.id == "github-token" for d in results)

    def test_github_pat_detected(self):
        text = "github_pat_11ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        results = detect_all(text)
        assert any(d.id == "github-token" for d in results)

    def test_private_key_pem_detected(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
        results = detect_all(text)
        assert any(d.id == "private-key-pem" for d in results)

    def test_generic_private_key_pem_detected(self):
        text = "-----BEGIN PRIVATE KEY-----\nMIIEow..."
        results = detect_all(text)
        assert any(d.id == "private-key-pem" for d in results)

    def test_jwt_detected(self):
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        results = detect_all(text)
        assert any(d.id == "jwt-token" for d in results)

    def test_stripe_live_key_detected(self):
        text = "STRIPE_KEY=" + _STRIPE_KEY
        results = detect_all(text)
        assert any(d.id == "stripe-key" for d in results)

    def test_anthropic_key_detected(self):
        text = "api_key = sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        results = detect_all(text)
        assert any(d.id == "anthropic-key" for d in results)

    def test_openai_key_detected(self):
        text = "key = sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"
        results = detect_all(text)
        assert any(d.id == "openai-key" for d in results)

    def test_bearer_token_detected(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefghijklmnopqrstuvwxyz"
        results = detect_all(text)
        assert any(d.id == "bearer-token" for d in results)

    def test_postgres_connection_string_detected(self):
        text = "DATABASE_URL=postgresql://user:supersecret@db.example.com:5432/mydb"
        results = detect_all(text)
        assert any(d.id == "db-connection-string" for d in results)

    def test_mongodb_connection_string_detected(self):
        text = "mongodb://admin:password123@cluster.mongodb.net/mydb"
        results = detect_all(text)
        assert any(d.id == "db-connection-string" for d in results)

    def test_private_key_assignment_detected(self):
        text = "private_key=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234"
        results = detect_all(text)
        assert any(d.id == "private-key-assignment" for d in results)

    def test_client_secret_detected(self):
        text = 'client_secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu01"'
        results = detect_all(text)
        assert any(d.id == "private-key-assignment" for d in results)

    def test_multiple_secrets_returns_multiple_detections(self):
        text = (
            "key=AKIAIOSFODNN7EXAMPLE and "
            + _STRIPE_KEY + " is also present"
        )
        results = detect_all(text)
        ids = {d.id for d in results}
        assert "aws-access-key" in ids
        assert "stripe-key" in ids

    def test_detection_has_correct_span(self):
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"Use key {key} to auth"
        results = detect_all(text)
        aws = next(d for d in results if d.id == "aws-access-key")
        assert text[aws.match_start : aws.match_end] == key

    def test_returns_detection_objects(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        results = detect_all(text)
        assert all(isinstance(d, Detection) for d in results)

    def test_no_false_positive_on_normal_sentence(self):
        safe = "Please help me refactor this Python function to be more readable."
        assert detect_all(safe) == []

    def test_no_false_positive_on_short_base64(self):
        # Short base64 strings that look like keys but aren't long enough
        assert detect_all("eyJ") == []  # too short for JWT


class TestRedact:
    def test_clean_text_unchanged(self):
        text = "Hello, no secrets here."
        redacted, detections = redact(text)
        assert redacted == text
        assert detections == []

    def test_aws_key_replaced_with_placeholder(self):
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"My key is {key} thanks"
        redacted, _ = redact(text)
        assert key not in redacted
        assert "[REDACTED:aws-access-key]" in redacted
        assert "My key is " in redacted
        assert " thanks" in redacted

    def test_placeholder_preserves_surrounding_text(self):
        text = "prefix AKIAIOSFODNN7EXAMPLE suffix"
        redacted, _ = redact(text)
        assert redacted == "prefix [REDACTED:aws-access-key] suffix"

    def test_multiple_different_secrets_both_redacted(self):
        text = "AKIAIOSFODNN7EXAMPLE and " + _STRIPE_KEY
        redacted, _ = redact(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert _STRIPE_KEY not in redacted
        assert "[REDACTED:aws-access-key]" in redacted
        assert "[REDACTED:stripe-key]" in redacted

    def test_returns_original_detections(self):
        text = "AKIAIOSFODNN7EXAMPLE"
        _, detections = redact(text)
        assert len(detections) >= 1
        assert detections[0].id == "aws-access-key"

    def test_empty_string_unchanged(self):
        redacted, detections = redact("")
        assert redacted == ""
        assert detections == []
