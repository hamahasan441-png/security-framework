from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from security_framework.core.audit import AuditLogger
from security_framework.core.scope import ScopePolicy


@dataclass
class HttpResponseSummary:
    url: str
    status_code: int
    elapsed_ms: float
    content_length: int
    text_preview: str


class RateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.min_interval = 1.0 / max(requests_per_second, 0.1)
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        delay = self.min_interval - (now - self._last)
        if delay > 0:
            time.sleep(delay)
        self._last = time.monotonic()


class SafeHttpClient:
    def __init__(
        self,
        scope: ScopePolicy,
        audit: AuditLogger,
        timeout_seconds: float = 10.0,
        verify_tls: bool = True,
        max_retries: int = 2,
        max_redirects: int = 3,
        requests_per_second: float = 2.0,
        user_agent: str = "InternalSecurityFramework/0.1 (+security-team)",
    ) -> None:
        self.scope = scope
        self.audit = audit
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls
        self.max_redirects = max_redirects
        self.rate_limiter = RateLimiter(requests_per_second)
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        retry = Retry(total=max_retries, backoff_factor=0.3, status_forcelist=(429, 500, 502, 503, 504), allowed_methods=("GET", "HEAD"))
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def get(self, url: str) -> requests.Response:
        request_id = uuid.uuid4().hex
        self.scope.validate_url(url)
        self.rate_limiter.wait()
        start = time.perf_counter()
        self.audit.log({"event": "http_request", "request_id": request_id, "method": "GET", "url": url})
        response = self.session.get(url, timeout=self.timeout_seconds, verify=self.verify_tls, allow_redirects=False)
        redirects = 0
        while response.is_redirect and redirects < self.max_redirects:
            location = response.headers.get("Location")
            if not location:
                break
            next_url = urljoin(response.url, location)
            self.scope.validate_url(next_url)
            response = self.session.get(next_url, timeout=self.timeout_seconds, verify=self.verify_tls, allow_redirects=False)
            redirects += 1
        elapsed_ms = (time.perf_counter() - start) * 1000
        self.audit.log({"event": "http_response", "request_id": request_id, "url": response.url, "status": response.status_code, "elapsed_ms": round(elapsed_ms, 2), "bytes": len(response.content)})
        return response
