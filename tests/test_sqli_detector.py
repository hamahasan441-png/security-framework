from security_framework.plugins.sqli_detector import (
    FormParser,
    ResponseProfile,
    _replace_query_param,
    _significant_difference,
)


def test_replace_query_param_updates_existing_value() -> None:
    url = _replace_query_param("https://example.com/search?q=abc&page=1", "q", "xyz")
    assert url == "https://example.com/search?q=xyz&page=1"


def test_replace_query_param_adds_missing_value() -> None:
    url = _replace_query_param("https://example.com/search", "q", "xyz")
    assert url == "https://example.com/search?q=xyz"


def test_form_parser_discovers_post_fields() -> None:
    parser = FormParser(base_url="https://example.com/base")
    parser.feed(
        '<form method="post" action="/login">'
        '<input type="text" name="username" value="">'
        '<input type="password" name="password" value="">'
        '<input type="submit" name="submit" value="Login">'
        '</form>'
    )
    assert len(parser.forms) == 1
    form = parser.forms[0]
    assert form.method == "POST"
    assert form.action_url == "https://example.com/login"
    assert sorted(form.fields) == ["password", "username"]


def test_significant_difference_detects_server_error_transition() -> None:
    baseline = ResponseProfile(
        status_code=200,
        elapsed_ms=100,
        content_length=100,
        content_type="text/html",
        title="OK",
        normalized_body="normal page",
    )
    observed = ResponseProfile(
        status_code=500,
        elapsed_ms=110,
        content_length=100,
        content_type="text/html",
        title="OK",
        normalized_body="normal page",
    )
    assert _significant_difference(baseline, observed)
