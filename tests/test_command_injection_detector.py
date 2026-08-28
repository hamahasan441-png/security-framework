from security_framework.plugins.command_injection_detector import (
    _raw_payload_reflected,
    _replace_query_param,
)


def test_replace_query_param_updates_existing_value() -> None:
    url = _replace_query_param("https://example.com/search?q=test&page=1", "q", "safe marker")
    assert "q=safe+marker" in url
    assert "page=1" in url


def test_replace_query_param_adds_missing_value() -> None:
    url = _replace_query_param("https://example.com/search", "q", "safe")
    assert url == "https://example.com/search?q=safe"


def test_raw_payload_reflection_detects_plain_reflection() -> None:
    assert _raw_payload_reflected("input was test; echo CMDI_SAFE_123", "test; echo CMDI_SAFE_123")


def test_raw_payload_reflection_ignores_marker_only() -> None:
    assert not _raw_payload_reflected("CMDI_SAFE_123", "test; echo CMDI_SAFE_123")
