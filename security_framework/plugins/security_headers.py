from __future__ import annotations

from security_framework.findings import Confidence, Evidence, Finding, Severity
from security_framework.plugins.base import CheckContext, SecurityCheck


class SecurityHeadersCheck(SecurityCheck):
    id = "security_headers"
    name = "Security headers"
    description = "Checks for common defensive HTTP response headers."

    REQUIRED_HEADERS = {
        "strict-transport-security": "Enable HSTS for HTTPS services.",
        "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
        "content-security-policy": "Add a restrictive Content-Security-Policy.",
        "referrer-policy": "Set a privacy-preserving Referrer-Policy.",
    }

    def run(self, context: CheckContext) -> list[Finding]:
        response = context.http.get(context.target_url)
        present = {key.lower() for key in response.headers.keys()}
        findings: list[Finding] = []
        missing = [header for header in self.REQUIRED_HEADERS if header not in present]
        if missing:
            findings.append(
                Finding(
                    title="Missing defensive HTTP security headers",
                    description="One or more recommended HTTP security headers are not present.",
                    asset=context.target_url,
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence=[Evidence(kind="headers", description="Missing headers", data={"missing": missing})],
                    remediation=[self.REQUIRED_HEADERS[item] for item in missing],
                    references=["https://owasp.org/www-project-secure-headers/"],
                )
            )
        return findings
