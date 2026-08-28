from __future__ import annotations

from dataclasses import dataclass, field

from security_framework.core.audit import AuditLogger
from security_framework.core.config import Config
from security_framework.core.http_client import SafeHttpClient
from security_framework.core.plugin_loader import load_checks
from security_framework.core.scope import ScopePolicy
from security_framework.discovery import SafeCrawler
from security_framework.findings import Finding
from security_framework.plugins import CheckContext


@dataclass
class AssessmentResult:
    findings: list[Finding] = field(default_factory=list)
    discovered_urls: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "discovered_urls": self.discovered_urls,
        }


class AssessmentEngine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.audit = AuditLogger()
        self.scope = ScopePolicy(
            allowed_domains=set(config.scope.allowed_domains),
            allowed_cidrs=set(config.scope.allowed_cidrs),
            allow_private_ranges=config.scope.allow_private_ranges,
        )
        self.http = SafeHttpClient(
            scope=self.scope,
            audit=self.audit,
            timeout_seconds=config.http.timeout_seconds,
            verify_tls=config.http.verify_tls,
            max_retries=config.http.max_retries,
            max_redirects=config.http.max_redirects,
            requests_per_second=config.http.requests_per_second,
            user_agent=config.http.user_agent,
        )
        self.checks = load_checks(config.plugins)

    def run(self) -> AssessmentResult:
        result = AssessmentResult()
        for target in self.config.targets:
            self.scope.validate_url(target.url)
            if self.config.crawler.enabled:
                crawler = SafeCrawler(
                    base_url=target.url,
                    http=self.http,
                    max_depth=self.config.crawler.max_depth,
                    max_urls=self.config.crawler.max_urls,
                    respect_robots_txt=self.config.crawler.respect_robots_txt,
                    safe_wordlist=self.config.crawler.safe_wordlist,
                )
                result.discovered_urls[target.url] = sorted(crawler.crawl())
            context = CheckContext(target_url=target.url, http=self.http)
            for check in self.checks:
                self.audit.log({"event": "check_start", "check_id": check.id, "target": target.url})
                findings = check.run(context)
                result.findings.extend(findings)
                self.audit.log({"event": "check_end", "check_id": check.id, "target": target.url, "findings": len(findings)})
        return result
