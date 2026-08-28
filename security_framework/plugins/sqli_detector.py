from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

from security_framework.core.redaction import redact
from security_framework.findings import Confidence, Evidence, Finding, Severity
from security_framework.plugins.base import CheckContext, SecurityCheck

HttpMethod = Literal["GET", "POST"]

SQL_ERROR_RE = re.compile(
    r"(?i)("
    r"sql syntax|syntax error.*sql|unclosed quotation|unterminated quoted string|"
    r"mysql|mariadb|postgresql|sqlite|oracle|ora-[0-9]{4,}|sqlstate|odbc|jdbc|"
    r"microsoft ole db|sql server|native client|db2 sql|firebird|"
    r"psycopg|pg_query|sqliteexception|mysql_fetch|mysqli_|pdoexception"
    r")"
)

# Safe, non-destructive input-validation probes. These are intentionally not
# exploit payloads and do not include DB sleep/extraction logic.
SAFE_PROBES: tuple[tuple[str, str], ...] = (
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("closing_parenthesis", ")"),
    ("backslash", "\\"),
    ("unicode_quote", "\u2019"),
    ("long_marker", "SECURITY_TEST_SQLI_MARKER_0123456789"),
)

IGNORED_INPUT_TYPES = {"submit", "button", "reset", "file", "image"}
TEXTUAL_INPUT_TYPES = {
    "",
    "text",
    "search",
    "email",
    "url",
    "tel",
    "number",
    "hidden",
    "password",
}


@dataclass(frozen=True)
class ResponseProfile:
    status_code: int
    elapsed_ms: float
    content_length: int
    content_type: str
    title: str
    normalized_body: str
    sql_error: str | None = None

    @classmethod
    def from_response(cls, response: requests.Response, elapsed_ms: float) -> "ResponseProfile":
        text = response.text if _looks_textual(response) else ""
        sql_match = SQL_ERROR_RE.search(text)
        return cls(
            status_code=response.status_code,
            elapsed_ms=elapsed_ms,
            content_length=len(response.content),
            content_type=response.headers.get("content-type", ""),
            title=_extract_title(text),
            normalized_body=_normalize_body(text),
            sql_error=redact(sql_match.group(0)) if sql_match else None,
        )


@dataclass(frozen=True)
class ParameterCandidate:
    method: HttpMethod
    url: str
    name: str
    baseline_value: str
    form_data: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class FormEndpoint:
    method: HttpMethod
    action_url: str
    fields: dict[str, str]


@dataclass
class FormParser(HTMLParser):
    base_url: str
    forms: list[FormEndpoint] = field(default_factory=list)
    _inside_form: bool = False
    _method: HttpMethod = "GET"
    _action_url: str = ""
    _fields: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        HTMLParser.__init__(self)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "form":
            raw_method = attrs_dict.get("method", "get").upper()
            self._method = "POST" if raw_method == "POST" else "GET"
            self._action_url = urljoin(self.base_url, attrs_dict.get("action", ""))
            self._fields = {}
            self._inside_form = True
            return

        if not self._inside_form:
            return

        if tag == "input":
            name = attrs_dict.get("name", "").strip()
            input_type = attrs_dict.get("type", "text").lower().strip()
            if name and input_type not in IGNORED_INPUT_TYPES and input_type in TEXTUAL_INPUT_TYPES:
                self._fields[name] = attrs_dict.get("value", "")
        elif tag == "textarea":
            name = attrs_dict.get("name", "").strip()
            if name:
                self._fields[name] = ""

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._inside_form:
            if self._fields:
                self.forms.append(
                    FormEndpoint(method=self._method, action_url=self._action_url, fields=dict(self._fields))
                )
            self._inside_form = False
            self._fields = {}


class SQLInjectionDetector(SecurityCheck):
    """Safe SQL injection detector for authorized staging assessments.

    The check uses non-destructive malformed-input probes, SQL error pattern
    detection, differential response comparison, and passive timing anomaly
    analysis. It deliberately does not perform data extraction, stacked queries,
    DB sleep payloads, WAF bypass mutations, or exploit chaining.
    """

    id = "sqli_detector"
    name = "SQL injection detector"
    description = "Detects SQL-injection indicators using safe defensive probes."

    def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = self._collect_candidates(context)
        context.http.audit.log(
            {"event": "sqli_detector_started", "target": context.target_url, "candidates": len(candidates)}
        )

        for candidate in candidates:
            finding = self._test_candidate(context, candidate)
            protected = finding is None
            context.http.audit.log(
                {
                    "event": "sqli_parameter_result",
                    "target": candidate.url,
                    "method": candidate.method,
                    "parameter": candidate.name,
                    "protected": protected,
                }
            )
            if finding:
                findings.append(finding)

        context.http.audit.log(
            {
                "event": "sqli_detector_finished",
                "target": context.target_url,
                "candidates": len(candidates),
                "findings": len(findings),
            }
        )
        return findings

    def _collect_candidates(self, context: CheckContext) -> list[ParameterCandidate]:
        candidates: list[ParameterCandidate] = []
        parsed = urlparse(context.target_url)
        seen: set[tuple[str, str, str]] = set()

        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            item = ParameterCandidate(method="GET", url=context.target_url, name=key, baseline_value=value)
            marker = (item.method, item.url, item.name)
            if marker not in seen:
                candidates.append(item)
                seen.add(marker)

        for form in self._discover_forms(context):
            for field_name, field_value in form.fields.items():
                item = ParameterCandidate(
                    method=form.method,
                    url=form.action_url,
                    name=field_name,
                    baseline_value=field_value,
                    form_data=dict(form.fields),
                )
                marker = (item.method, item.url, item.name)
                if marker not in seen:
                    candidates.append(item)
                    seen.add(marker)

        return candidates

    def _discover_forms(self, context: CheckContext) -> list[FormEndpoint]:
        try:
            response, _profile = self._profile_get(context, context.target_url)
        except Exception as exc:
            context.http.audit.log(
                {"event": "sqli_form_discovery_error", "target": context.target_url, "error": str(exc)}
            )
            return []

        if "text/html" not in response.headers.get("content-type", "").lower():
            return []

        parser = FormParser(base_url=response.url)
        parser.feed(response.text[:2_000_000])
        safe_forms: list[FormEndpoint] = []
        for form in parser.forms:
            try:
                context.http.scope.validate_url(form.action_url)
            except Exception as exc:
                context.http.audit.log(
                    {"event": "sqli_form_out_of_scope", "form_url": form.action_url, "reason": str(exc)}
                )
                continue
            safe_forms.append(form)
        return safe_forms

    def _test_candidate(self, context: CheckContext, candidate: ParameterCandidate) -> Finding | None:
        baseline_response, baseline = self._send_candidate(context, candidate, candidate.baseline_value)
        evidence: list[Evidence] = []
        differential_hits = 0
        timing_hits = 0
        error_hits = 0

        for probe_name, probe_value in SAFE_PROBES:
            test_value = f"{candidate.baseline_value}{probe_value}"
            try:
                response, profile = self._send_candidate(context, candidate, test_value)
            except Exception as exc:
                context.http.audit.log(
                    {
                        "event": "sqli_probe_error",
                        "target": candidate.url,
                        "method": candidate.method,
                        "parameter": candidate.name,
                        "probe": probe_name,
                        "error": str(exc),
                    }
                )
                continue

            if profile.sql_error and not baseline.sql_error:
                error_hits += 1
                evidence.append(
                    Evidence(
                        kind="sql_error_indicator",
                        description="Response contained a database-related error indicator only after a safe malformed-input probe.",
                        data={
                            "method": candidate.method,
                            "url": response.url,
                            "parameter": candidate.name,
                            "probe": probe_name,
                            "status_code": profile.status_code,
                            "sql_error_indicator": profile.sql_error,
                            "response_preview": redact(response.text[:500]),
                        },
                    )
                )

            if _significant_difference(baseline, profile):
                differential_hits += 1

            if _timing_anomaly(baseline, profile):
                timing_hits += 1

        if differential_hits >= 2:
            evidence.append(
                Evidence(
                    kind="differential_response",
                    description="Multiple safe probes produced response differences compared with the baseline.",
                    data={
                        "method": candidate.method,
                        "url": baseline_response.url,
                        "parameter": candidate.name,
                        "baseline_status": baseline.status_code,
                        "baseline_length": baseline.content_length,
                        "differential_probe_count": differential_hits,
                    },
                )
            )

        if timing_hits >= 2:
            evidence.append(
                Evidence(
                    kind="timing_anomaly",
                    description="Multiple safe probes produced slower responses than the baseline. Treat as a hypothesis requiring manual validation.",
                    data={
                        "method": candidate.method,
                        "url": baseline_response.url,
                        "parameter": candidate.name,
                        "baseline_elapsed_ms": round(baseline.elapsed_ms, 2),
                        "timing_probe_count": timing_hits,
                    },
                )
            )

        if not evidence:
            return None

        severity = Severity.HIGH if error_hits > 0 and len(evidence) >= 2 else Severity.MEDIUM
        confidence = Confidence.HIGH if error_hits > 0 and len(evidence) >= 2 else Confidence.MEDIUM
        if timing_hits >= 2 and error_hits == 0:
            confidence = Confidence.LOW
            severity = Severity.LOW

        return Finding(
            title="Possible SQL injection weakness detected",
            description=(
                "A parameter showed SQL-injection indicators during safe defensive testing. "
                "This finding is non-destructive and should be validated with server-side logs, "
                "query instrumentation, or a staging-only test harness before being treated as confirmed."
            ),
            asset=f"{candidate.method} {candidate.url} parameter={candidate.name}",
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            remediation=[
                "Use parameterized queries or prepared statements for all database access.",
                "Do not concatenate user-controlled input into SQL strings.",
                "Normalize and validate input at trust boundaries.",
                "Return generic error pages; log detailed errors server-side only.",
                "Add regression tests that exercise this parameter with malformed input.",
                "Use WAF telemetry only as a compensating signal, not as the primary fix.",
            ],
            cwe="CWE-89",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://owasp.org/www-project-web-security-testing-guide/",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
        )

    def _send_candidate(
        self, context: CheckContext, candidate: ParameterCandidate, value: str
    ) -> tuple[requests.Response, ResponseProfile]:
        if candidate.method == "GET":
            url = _replace_query_param(candidate.url, candidate.name, value)
            return self._profile_get(context, url)

        data = dict(candidate.form_data)
        data[candidate.name] = value
        return self._profile_post(context, candidate.url, data)

    def _profile_get(self, context: CheckContext, url: str) -> tuple[requests.Response, ResponseProfile]:
        start = time.perf_counter()
        response = context.http.get(url)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return response, ResponseProfile.from_response(response, elapsed_ms)

    def _profile_post(
        self, context: CheckContext, url: str, data: dict[str, str]
    ) -> tuple[requests.Response, ResponseProfile]:
        start = time.perf_counter()
        response = context.http.post_form(url, data=data)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return response, ResponseProfile.from_response(response, elapsed_ms)


def _replace_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated: list[tuple[str, str]] = []
    found = False
    for key, existing in pairs:
        if key == name:
            updated.append((key, value))
            found = True
        else:
            updated.append((key, existing))
    if not found:
        updated.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))


def _looks_textual(response: requests.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    return any(item in content_type for item in ("text/", "json", "xml", "html", "javascript"))


def _extract_title(text: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def _normalize_body(text: str) -> str:
    text = text.lower()[:20_000]
    text = re.sub(r"[a-f0-9]{16,}", "<hex>", text)
    text = re.sub(r"\b\d{2,}\b", "<num>", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _significant_difference(baseline: ResponseProfile, observed: ResponseProfile) -> bool:
    if observed.status_code != baseline.status_code and observed.status_code >= 500:
        return True
    if baseline.title and observed.title and baseline.title != observed.title:
        return True

    base_len = max(baseline.content_length, 1)
    length_delta = abs(observed.content_length - baseline.content_length) / base_len
    similarity = SequenceMatcher(None, baseline.normalized_body[:8_000], observed.normalized_body[:8_000]).ratio()
    return length_delta >= 0.30 and similarity <= 0.85


def _timing_anomaly(baseline: ResponseProfile, observed: ResponseProfile) -> bool:
    # Passive timing anomaly only. This does not attempt DB sleep or delay payloads.
    minimum_delta_ms = 1_500.0
    multiplier = 3.0
    return observed.elapsed_ms >= max(baseline.elapsed_ms * multiplier, baseline.elapsed_ms + minimum_delta_ms)
