from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

import requests

from security_framework.core.http_client import SafeHttpClient
from security_framework.core.scope import ScopeError

DEFAULT_SAFE_WORDLIST = ["/", "/robots.txt", "/sitemap.xml", "/health", "/status", "/login"]
HTML_TYPES = ("text/html", "application/xhtml+xml")
SKIP_EXTENSIONS = (
    ".7z",
    ".avi",
    ".bmp",
    ".css",
    ".dmg",
    ".exe",
    ".gif",
    ".gz",
    ".ico",
    ".iso",
    ".jpeg",
    ".jpg",
    ".js",
    ".mov",
    ".mp3",
    ".mp4",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".tgz",
    ".webp",
    ".zip",
)


class LinkParser(HTMLParser):
    """Minimal HTML link extractor using the standard library only."""

    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag not in {"a", "link"}:
            return
        for key, value in attrs:
            if key and key.lower() == "href" and value:
                self.links.add(value)


@dataclass
class CrawlResult:
    discovered_urls: set[str] = field(default_factory=set)
    blocked_urls: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


@dataclass
class SafeCrawler:
    """Robots-aware, scoped crawler for defensive discovery only."""

    base_url: str
    http: SafeHttpClient
    max_depth: int = 2
    max_urls: int = 100
    respect_robots_txt: bool = True
    safe_wordlist: list[str] = field(default_factory=lambda: DEFAULT_SAFE_WORDLIST.copy())

    @classmethod
    def from_config(cls, base_url: str, http: SafeHttpClient, config: object) -> "SafeCrawler":
        return cls(
            base_url=base_url,
            http=http,
            max_depth=int(getattr(config, "max_depth", 2)),
            max_urls=int(getattr(config, "max_urls", 100)),
            respect_robots_txt=bool(getattr(config, "respect_robots_txt", True)),
            safe_wordlist=list(getattr(config, "safe_wordlist", DEFAULT_SAFE_WORDLIST)),
        )

    def crawl(self) -> set[str]:
        """Return discovered in-scope URLs. Kept for backward compatibility."""
        return self.crawl_with_details().discovered_urls

    def crawl_with_details(self) -> CrawlResult:
        self.base_url = normalize_url(self.base_url)
        self.http.scope.validate_url(self.base_url)
        self.http.audit.log(
            {
                "event": "crawler_started",
                "base_url": self.base_url,
                "max_depth": self.max_depth,
                "max_urls": self.max_urls,
                "respect_robots_txt": self.respect_robots_txt,
            }
        )

        result = CrawlResult()
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])
        robots = self._load_robots()

        for path in self._safe_paths():
            queue.append((normalize_url(urljoin(self.base_url, path)), 0))

        while queue and len(result.discovered_urls) < self.max_urls:
            url, depth = queue.popleft()
            url = normalize_url(url)
            if url in visited or depth > self.max_depth or should_skip_url(url):
                continue
            visited.add(url)

            try:
                self.http.scope.validate_url(url)
            except ScopeError as exc:
                result.blocked_urls[url] = str(exc)
                self.http.audit.log({"event": "crawler_url_blocked", "url": url, "reason": str(exc)})
                continue

            if robots and not robots.can_fetch(self.http.session.headers.get("User-Agent", "*"), url):
                result.blocked_urls[url] = "blocked by robots.txt"
                self.http.audit.log({"event": "crawler_url_robots_blocked", "url": url})
                continue

            try:
                response = self.http.get(url)
            except (requests.RequestException, ScopeError, ValueError) as exc:
                result.errors[url] = f"{type(exc).__name__}: {exc}"
                self.http.audit.log({"event": "crawler_url_error", "url": url, "error": str(exc)})
                continue

            if response.status_code < 400:
                result.discovered_urls.add(url)
            elif response.status_code in {401, 403}:
                # Authorization boundaries are still useful discovery signals.
                result.discovered_urls.add(url)

            if depth >= self.max_depth or not is_html_response(response):
                continue

            parser = LinkParser()
            try:
                parser.feed(response.text)
            except Exception as exc:  # HTMLParser can fail on malformed markup.
                result.errors[url] = f"HTML parse error: {exc}"
                continue

            for href in parser.links:
                child = normalize_url(urljoin(url, href))
                if same_origin(self.base_url, child) and child not in visited:
                    queue.append((child, depth + 1))

        self.http.audit.log(
            {
                "event": "crawler_finished",
                "base_url": self.base_url,
                "discovered": len(result.discovered_urls),
                "blocked": len(result.blocked_urls),
                "errors": len(result.errors),
            }
        )
        return result

    def _load_robots(self) -> RobotFileParser | None:
        if not self.respect_robots_txt:
            return None
        robots_url = normalize_url(urljoin(self.base_url, "/robots.txt"))
        parser = RobotFileParser(robots_url)
        try:
            response = self.http.get(robots_url)
        except Exception as exc:
            self.http.audit.log({"event": "crawler_robots_unavailable", "url": robots_url, "error": str(exc)})
            return None
        parser.parse(response.text.splitlines())
        self.http.audit.log({"event": "crawler_robots_loaded", "url": robots_url, "status": response.status_code})
        return parser

    def _safe_paths(self) -> list[str]:
        paths: list[str] = []
        for item in self.safe_wordlist:
            path = str(item).strip()
            if not path:
                continue
            if not path.startswith("/"):
                path = "/" + path
            lowered = path.lower()
            if any(sensitive in lowered for sensitive in (".env", ".git", "wp-config", "passwd", "shadow")):
                self.http.audit.log({"event": "crawler_wordlist_entry_rejected", "path": path})
                continue
            paths.append(path)
        return sorted(set(paths))


def normalize_url(url: str) -> str:
    url, _fragment = urldefrag(url)
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", parsed.query, ""))


def same_origin(a: str, b: str) -> bool:
    pa = urlparse(a)
    pb = urlparse(b)
    return pa.scheme.lower() == pb.scheme.lower() and pa.netloc.lower() == pb.netloc.lower()


def is_html_response(response: requests.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    return any(kind in content_type for kind in HTML_TYPES)


def should_skip_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in SKIP_EXTENSIONS)
