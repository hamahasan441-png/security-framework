from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import yaml

DEFAULT_PLUGINS = ["security_framework.plugins.security_headers.SecurityHeadersCheck"]
DEFAULT_SAFE_WORDLIST = ["/", "/robots.txt", "/sitemap.xml", "/health", "/status", "/login"]
VALID_RUN_MODES = {"safe_production", "authorized_deep", "isolated_lab"}


class ConfigError(ValueError):
    """Raised when the scanner configuration is unsafe or invalid."""


@dataclass(frozen=True)
class TargetConfig:
    """One explicitly authorized assessment target."""

    url: str
    name: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.url, str) or not self.url.strip():
            raise ConfigError("target.url must be a non-empty string")
        if not self.url.startswith(("http://", "https://")):
            raise ConfigError(f"target.url must start with http:// or https://: {self.url}")


@dataclass(frozen=True)
class ScopeConfig:
    """Domain and network boundaries enforced before every network operation."""

    allowed_domains: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    allow_private_ranges: bool = False
    allow_redirects: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_domains", _clean_domains(self.allowed_domains))
        object.__setattr__(self, "allowed_cidrs", _clean_list(self.allowed_cidrs))
        if not self.allowed_domains and not self.allowed_cidrs:
            raise ConfigError("scope.allowed_domains or scope.allowed_cidrs must be configured")


@dataclass(frozen=True)
class HttpConfig:
    """Safe HTTP transport defaults. TLS verification is enabled by default."""

    timeout_seconds: float = 10.0
    verify_tls: bool = True
    max_redirects: int = 3
    max_retries: int = 2
    retry_backoff_seconds: float = 0.35
    requests_per_second: float = 2.0
    user_agent: str = "InternalSecurityFramework/0.2 (+security-team)"
    max_response_bytes: int = 2_000_000

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0 or self.timeout_seconds > 120:
            raise ConfigError("http.timeout_seconds must be between 0 and 120")
        if self.max_redirects < 0 or self.max_redirects > 10:
            raise ConfigError("http.max_redirects must be between 0 and 10")
        if self.max_retries < 0 or self.max_retries > 5:
            raise ConfigError("http.max_retries must be between 0 and 5")
        if self.retry_backoff_seconds < 0 or self.retry_backoff_seconds > 10:
            raise ConfigError("http.retry_backoff_seconds must be between 0 and 10")
        if self.requests_per_second <= 0 or self.requests_per_second > 50:
            raise ConfigError("http.requests_per_second must be between 0 and 50")
        if self.max_response_bytes < 1_024:
            raise ConfigError("http.max_response_bytes must be at least 1024")
        if not self.verify_tls:
            # Allowed for lab use, but callers should log this clearly.
            pass


@dataclass(frozen=True)
class AuditConfig:
    """Structured audit log configuration."""

    path: str | None = "reports/audit.jsonl"
    echo: bool = False


@dataclass(frozen=True)
class CrawlerConfig:
    """Safe discovery crawler settings."""

    enabled: bool = True
    max_depth: int = 2
    max_urls: int = 100
    respect_robots_txt: bool = True
    safe_wordlist: list[str] = field(default_factory=lambda: DEFAULT_SAFE_WORDLIST.copy())

    def __post_init__(self) -> None:
        if self.max_depth < 0 or self.max_depth > 5:
            raise ConfigError("crawler.max_depth must be between 0 and 5")
        if self.max_urls <= 0 or self.max_urls > 5_000:
            raise ConfigError("crawler.max_urls must be between 1 and 5000")
        safe_paths: list[str] = []
        for item in self.safe_wordlist:
            if not isinstance(item, str) or not item.strip():
                continue
            path = item.strip()
            if not path.startswith("/"):
                path = "/" + path
            # Do not ship sensitive probes as defaults. Operators can add explicit checks elsewhere.
            if any(part in path.lower() for part in (".env", ".git", "wp-config", "passwd", "shadow")):
                raise ConfigError(f"crawler.safe_wordlist contains unsafe sensitive path: {path}")
            safe_paths.append(path)
        object.__setattr__(self, "safe_wordlist", sorted(set(safe_paths)))


@dataclass(frozen=True)
class Config:
    """Top-level scanner configuration."""

    targets: list[TargetConfig]
    scope: ScopeConfig
    http: HttpConfig = field(default_factory=HttpConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    plugins: list[str] = field(default_factory=lambda: DEFAULT_PLUGINS.copy())
    run_mode: str = "safe_production"

    def __post_init__(self) -> None:
        if self.run_mode not in VALID_RUN_MODES:
            raise ConfigError(f"run_mode must be one of: {sorted(VALID_RUN_MODES)}")
        if not self.targets:
            raise ConfigError("At least one target is required")
        object.__setattr__(self, "plugins", _clean_list(self.plugins) or DEFAULT_PLUGINS.copy())

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Config":
        config_path = Path(path)
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ConfigError("Config root must be a mapping")
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        targets_raw = raw.get("targets", [])
        if not isinstance(targets_raw, list) or not targets_raw:
            raise ConfigError("targets must be a non-empty list")

        targets: list[TargetConfig] = []
        for item in targets_raw:
            if isinstance(item, str):
                targets.append(TargetConfig(url=item))
            elif isinstance(item, dict):
                targets.append(TargetConfig(**item))
            else:
                raise ConfigError("each target must be a URL string or mapping")

        return cls(
            targets=targets,
            scope=ScopeConfig(**_mapping(raw.get("scope", {}), "scope")),
            http=HttpConfig(**_mapping(raw.get("http", {}), "http")),
            crawler=CrawlerConfig(**_mapping(raw.get("crawler", {}), "crawler")),
            audit=AuditConfig(**_mapping(raw.get("audit", {}), "audit")),
            plugins=_clean_list(raw.get("plugins", DEFAULT_PLUGINS)),
            run_mode=str(raw.get("run_mode", "safe_production")),
        )


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value


def _clean_list(value: Iterable[Any]) -> list[str]:
    return [str(item).strip() for item in value if str(item).strip()]


def _clean_domains(value: Iterable[Any]) -> list[str]:
    domains: list[str] = []
    for item in value:
        domain = str(item).strip().lower().strip(".")
        if not domain:
            continue
        if "://" in domain or "/" in domain:
            raise ConfigError(f"allowed domain must be a hostname, not a URL: {item}")
        domains.append(domain)
    return sorted(set(domains))
