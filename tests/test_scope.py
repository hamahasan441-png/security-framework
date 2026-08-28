import pytest

from security_framework.core.scope import ScopeError, ScopePolicy


def test_blocks_unsupported_scheme() -> None:
    policy = ScopePolicy(allowed_domains={"example.com"})
    with pytest.raises(ScopeError):
        policy.validate_url("file:///etc/passwd")


def test_blocks_out_of_domain() -> None:
    policy = ScopePolicy(allowed_domains={"example.com"})
    with pytest.raises(ScopeError):
        policy.validate_url("https://openai.com/")
