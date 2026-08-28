from security_framework.core.redaction import redact


def test_redacts_bearer_token() -> None:
    assert "secret" not in redact("Authorization: Bearer secret.token.value")
    assert "[REDACTED]" in redact("Authorization: Bearer secret.token.value")


def test_redacts_password() -> None:
    assert "hunter2" not in redact("password=hunter2")
