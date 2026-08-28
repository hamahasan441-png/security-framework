from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class TargetConfig:
    url: str


@dataclass(frozen=True)
class ScopeConfig:
    allowed_domains: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    allow_private_ranges: bool = False


@dataclass(frozen=True)
class HttpConfig:
    timeout_seconds: float = 10.0
    verify_tls: bool = True
    max_redirects: int = 3
    max_retries: int = 2
    requests_per_second: float = 2.0
    user_agent: str = "InternalSecurityFramework/0.1 (+security-team)"


@dataclass(frozen=True)
class CrawlerConfig:
    enabled: bool = True
    max_depth: int = 2
    max_urls: int = 100
    respect_robots_txt: bool = True
    safe_wordlist: list[str] = field(default_factory=lambda: ["/", "/robots.txt", "/sitemap.xml", "/health", "/status", "/login"])


@dataclass(frozen=True)
class Config:
    targets: list[TargetConfig]
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    plugins: list[str] = field(default_factory=lambda: ["security_framework.plugins.security_headers.SecurityHeadersCheck"])

    @classmethod
    def from_yaml(cls, path: Path) -> "Config":
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        targets = [TargetConfig(**item) for item in raw.get("targets", [])]
        if not targets:
            raise ValueError("At least one target is required")
        return cls(
            targets=targets,
            scope=ScopeConfig(**raw.get("scope", {})),
            http=HttpConfig(**raw.get("http", {})),
            crawler=CrawlerConfig(**raw.get("crawler", {})),
            plugins=list(raw.get("plugins", cls.__dataclass_fields__["plugins"].default_factory())),  # type: ignore[misc]
        )
