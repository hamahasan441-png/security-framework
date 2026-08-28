from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from security_framework.core.http_client import SafeHttpClient
from security_framework.core.scope import ScopeError


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.links.add(value)


@dataclass
class SafeCrawler:
    base_url: str
    http: SafeHttpClient
    max_depth: int = 2
    max_urls: int = 100
    respect_robots_txt: bool = True
    safe_wordlist: list[str] = field(default_factory=lambda: ["/", "/robots.txt", "/sitemap.xml", "/health", "/status", "/login"])

    def crawl(self) -> set[str]:
        discovered: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])
        robots = self._load_robots()
        for path in self.safe_wordlist:
            queue.append((urljoin(self.base_url, path), 0))
        while queue and len(discovered) < self.max_urls:
            url, depth = queue.popleft()
            url = normalize_url(url)
            if url in discovered or depth > self.max_depth:
                continue
            try:
                self.http.scope.validate_url(url)
            except ScopeError:
                continue
            if robots and not robots.can_fetch("*", url):
                continue
            try:
                response = self.http.get(url)
            except Exception:
                continue
            discovered.add(url)
            content_type = response.headers.get("content-type", "")
            if depth < self.max_depth and "text/html" in content_type.lower() and len(response.text) < 2_000_000:
                parser = LinkParser()
                parser.feed(response.text)
                for href in parser.links:
                    child = normalize_url(urljoin(url, href))
                    if same_origin(self.base_url, child):
                        queue.append((child, depth + 1))
        return discovered

    def _load_robots(self) -> RobotFileParser | None:
        if not self.respect_robots_txt:
            return None
        robots_url = urljoin(self.base_url, "/robots.txt")
        parser = RobotFileParser(robots_url)
        try:
            response = self.http.get(robots_url)
            parser.parse(response.text.splitlines())
            return parser
        except Exception:
            return None


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", parsed.query, ""))


def same_origin(a: str, b: str) -> bool:
    pa = urlparse(a)
    pb = urlparse(b)
    return pa.scheme == pb.scheme and pa.netloc.lower() == pb.netloc.lower()
