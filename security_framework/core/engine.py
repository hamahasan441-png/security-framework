from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

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
        audit_path = Path(config.audit.path) if config.audit.path else None
        self.audit = AuditLogger(path=audit_path, echo=config.audit.echo)
        self.scope = ScopePolicy.from_config(config.scope)
        self.http = SafeHttpClient.from_config(scope=self.scope, audit=self.audit, config=config.http)
        self.checks = load_checks(config.plugins)

    def run(self) -> AssessmentResult:
        self.audit.log(
            {
                "event": "assessment_started",
                "run_mode": self.config.run_mode,
                "targets": [target.url for target in self.config.targets],
                "plugins": self.config.plugins,
            }
        )
        result = AssessmentResult()
        for target in self.config.targets:
            self.scope.validate_url(target.url)
            if self.config.crawler.enabled:
                crawler = SafeCrawler.from_config(base_url=target.url, http=self.http, config=self.config.crawler)
                crawl_result = crawler.crawl_with_details()
                result.discovered_urls[target.url] = sorted(crawl_result.discovered_urls)

            context = CheckContext(target_url=target.url, http=self.http)
            for check in self.checks:
                self.audit.log({"event": "check_start", "check_id": check.id, "target": target.url})
                findings = check.run(context)
                result.findings.extend(findings)
                self.audit.log(
                    {
                        "event": "check_end",
                        "check_id": check.id,
                        "target": target.url,
                        "findings": len(findings),
                    }
                )
        self.audit.log(
            {
                "event": "assessment_finished",
                "finding_count": len(result.findings),
                "discovered_target_count": len(result.discovered_urls),
            }
        )
        return result
