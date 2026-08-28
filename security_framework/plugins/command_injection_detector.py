from __future__ import annotations

import html
import re
import uuid
from dataclasses import dataclass
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from security_framework.core.redaction import redact
from security_framework.findings import Confidence, Evidence, Finding, Severity
from security_framework.plugins.base import CheckContext, SecurityCheck

InjectionSurface = Literal["query", "header", "cookie"]

TEXTUAL_CONTENT_TYPES = ("text/", "html", "json", "xml", "javascript")
DEFAULT_HEADER_CANDIDATES = (
    "User-Agent",
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Referer",
)
DEFAULT_COOKIE_CANDIDATES = ("security_test", "debug", "lang", "session")


@dataclass(frozen=True)
class CommandProbe:
    name: str
    value: str
    marker: str
    expects_command_output: bool


@dataclass(frozen=True)
class CommandCandidate:
    surface: InjectionSurface
    url: str
    name: str
    baseline_value: str


@dataclass(frozen=True)
class ResponseObservation:
    status_code: int
    content_length: int
    content_type: str
    body: str

    @classmethod
    def from_response(cls, response: requests.Response) -> "ResponseObservation":
        content_type = response.headers.get("content-type", "")
        body = response.text if _looks_textual(response) else ""
        return cls(
            status_code=response.status_code,
            content_length=len(response.content),
            content_type=content_type,
            body=body[:200_000],
        )


class CommandInjectionDetector(SecurityCheck):
    """Safe command injection detector for authorized staging checks.

    This plugin tests query parameters, selected headers, and selected cookies
    with unique echo markers. It does not run identity, system-discovery,
    network, file-read, shell, persistence, or outbound callback commands.

    False-positive guard: if the raw submitted value is simply reflected back by
    the application, the observation is classified as reflection, not command
    execution. Findings are emitted only when a unique marker appears without
    the full submitted payload being reflected.
    """

    id = "command_injection_detector"
    name = "Command injection detector"
    description = "Detects command-injection indicators using safe echo-marker probes."

    def run(self, context: CheckContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = self._collect_candidates(context)
        context.http.audit.log(
            {
                "event": "cmdi_detector_started",
                "target": context.target_url,
                "candidates": len(candidates),
            }
        )

        for candidate in candidates:
            finding = self._test_candidate(context, candidate)
            context.http.audit.log(
                {
                    "event": "cmdi_candidate_result",
                    "target": candidate.url,
                    "surface": candidate.surface,
                    "name": candidate.name,
                    "protected": finding is None,
                }
            )
            if finding:
                findings.append(finding)

        context.http.audit.log(
            {
                "event": "cmdi_detector_finished",
                "target": context.target_url,
                "candidates": len(candidates),
                "findings": len(findings),
            }
        )
        return findings

    def _collect_candidates(self, context: CheckContext) -> list[CommandCandidate]:
        parsed = urlparse(context.target_url)
        candidates: list[CommandCandidate] = []
        seen: set[tuple[str, str, str]] = set()

        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            candidate = CommandCandidate(
                surface="query",
                url=context.target_url,
                name=key,
                baseline_value=value,
            )
            marker = (candidate.surface, candidate.url, candidate.name)
            if marker not in seen:
                candidates.append(candidate)
                seen.add(marker)

        for header_name in DEFAULT_HEADER_CANDIDATES:
            candidate = CommandCandidate(
                surface="header",
                url=context.target_url,
                name=header_name,
                baseline_value=_safe_header_baseline(header_name),
            )
            marker = (candidate.surface, candidate.url, candidate.name)
            if marker not in seen:
                candidates.append(candidate)
                seen.add(marker)

        baseline_cookies = self._discover_cookie_names(context)
        cookie_names = sorted(set(DEFAULT_COOKIE_CANDIDATES).union(baseline_cookies))
        for cookie_name in cookie_names:
            candidate = CommandCandidate(
                surface="cookie",
                url=context.target_url,
                name=cookie_name,
                baseline_value="security_test",
            )
            marker = (candidate.surface, candidate.url, candidate.name)
            if marker not in seen:
                candidates.append(candidate)
                seen.add(marker)

        return candidates

    def _discover_cookie_names(self, context: CheckContext) -> set[str]:
        try:
            response = context.http.get(context.target_url)
        except Exception as exc:
            context.http.audit.log(
                {"event": "cmdi_cookie_discovery_error", "target": context.target_url, "error": str(exc)}
            )
            return set()
        return {cookie.name for cookie in response.cookies}

    def _test_candidate(self, context: CheckContext, candidate: CommandCandidate) -> Finding | None:
        evidence: list[Evidence] = []
        reflection_hits = 0
        command_indicator_hits = 0

        for probe in self._build_probes(candidate.baseline_value):
            try:
                response = self._send_probe(context, candidate, probe.value)
            except Exception as exc:
                context.http.audit.log(
                    {
                        "event": "cmdi_probe_error",
                        "target": candidate.url,
                        "surface": candidate.surface,
                        "name": candidate.name,
                        "probe": probe.name,
                        "error": str(exc),
                    }
                )
                continue

            observation = ResponseObservation.from_response(response)
            marker_seen = _contains_marker(observation.body, probe.marker)
            raw_reflected = _raw_payload_reflected(observation.body, probe.value)

            if marker_seen and raw_reflected:
                reflection_hits += 1
                continue

            if marker_seen and probe.expects_command_output:
                command_indicator_hits += 1
                evidence.append(
                    Evidence(
                        kind="command_output_marker",
                        description=(
                            "A unique echo marker appeared in the response without the full submitted "
                            "input being reflected. This is a command-injection indicator that should "
                            "be validated in staging with server-side logs."
                        ),
                        data={
                            "surface": candidate.surface,
                            "url": response.url,
                            "name": candidate.name,
                            "probe": probe.name,
                            "status_code": observation.status_code,
                            "content_type": observation.content_type,
                            "marker": probe.marker,
                            "response_preview": redact(observation.body[:500]),
                        },
                    )
                )

        if not evidence:
            return None

        confidence = Confidence.HIGH if command_indicator_hits >= 2 else Confidence.MEDIUM
        severity = Severity.HIGH if command_indicator_hits >= 2 else Severity.MEDIUM
        if reflection_hits > 0 and command_indicator_hits == 1:
            confidence = Confidence.LOW

        return Finding(
            title="Possible command injection weakness detected",
            description=(
                "A request input produced a command-output marker during safe defensive testing. "
                "The plugin used only echo-marker probes and did not run identity, discovery, "
                "network, file-read, shell, persistence, or callback commands. Validate the finding "
                "with application logs and command-execution instrumentation in staging."
            ),
            asset=f"{candidate.surface}:{candidate.name} {candidate.url}",
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            remediation=[
                "Never pass user-controlled input to shell interpreters or OS command APIs.",
                "Use safe library calls instead of shell commands whenever possible.",
                "If process execution is unavoidable, pass arguments as an array with shell=False.",
                "Allowlist expected values and reject shell metacharacters at trust boundaries.",
                "Run application processes with least privilege and restrictive sandboxing.",
                "Add regression tests for this input surface using safe command-marker probes.",
            ],
            cwe="CWE-78",
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
        )

    def _build_probes(self, baseline_value: str) -> list[CommandProbe]:
        marker_a = "CMDI_SAFE_" + uuid.uuid4().hex[:12]
        marker_b = "CMDI_SAFE_" + uuid.uuid4().hex[:12]
        marker_c = "CMDI_SAFE_" + uuid.uuid4().hex[:12]
        prefix = baseline_value or "security_test"
        return [
            CommandProbe(
                name="literal_marker_reflection_control",
                value=f"{prefix}_{marker_a}",
                marker=marker_a,
                expects_command_output=False,
            ),
            CommandProbe(
                name="posix_echo_semicolon",
                value=f"{prefix}; echo {marker_b}",
                marker=marker_b,
                expects_command_output=True,
            ),
            CommandProbe(
                name="posix_echo_and_and",
                value=f"{prefix} && echo {marker_c}",
                marker=marker_c,
                expects_command_output=True,
            ),
        ]

    def _send_probe(
        self, context: CheckContext, candidate: CommandCandidate, value: str
    ) -> requests.Response:
        if candidate.surface == "query":
            return context.http.get(_replace_query_param(candidate.url, candidate.name, value))
        if candidate.surface == "header":
            return context.http.get(candidate.url, headers={candidate.name: value})
        if candidate.surface == "cookie":
            return context.http.get(candidate.url, cookies={candidate.name: value})
        raise ValueError(f"unsupported injection surface: {candidate.surface}")


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
    return any(item in content_type for item in TEXTUAL_CONTENT_TYPES)


def _contains_marker(body: str, marker: str) -> bool:
    return marker in body or html.escape(marker) in body


def _raw_payload_reflected(body: str, payload: str) -> bool:
    compact_body = _normalize_for_reflection(body)
    candidates = {
        payload,
        html.escape(payload),
        payload.replace(" ", "+"),
        payload.replace(" ", "%20"),
    }
    return any(_normalize_for_reflection(candidate) in compact_body for candidate in candidates)


def _normalize_for_reflection(value: str) -> str:
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value)
    return value.strip().lower()


def _safe_header_baseline(header_name: str) -> str:
    if header_name.lower() in {"x-forwarded-for", "x-real-ip"}:
        return "198.51.100.10"
    if header_name.lower() == "referer":
        return "https://security-test.local/"
    return "security-test"
