from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from threading import Lock
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from security_framework.core.audit import AuditLogger
from security_framework.core.scope import ScopeError, ScopePolicy


@dataclass(frozen=True)
class HttpResponseSummary:
    url: str
    status_code: int
    elapsed_ms: float
    content_length: int
    text_preview: str


class RateLimiter:
    """Simple thread-safe global rate limiter."""

    def __init__(self, requests_per_second: float) -> None:
        self.min_interval = 1.0 / max(float(requests_per_second), 0.1)
        self._last_request = 0.0
        self._lock = Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last_request)
            if delay > 0:
                time.sleep(delay)
            self._last_request = time.monotonic()


class SafeHttpClient:
    """Centralized, policy-enforced HTTP client.

    Every request is scope-checked, rate-limited, timeout-bounded, TLS-verified by
    default, and audited. Redirects are followed manually so each hop is checked
    against scope before another connection is opened.
    """

    def __init__(
        self,
        scope: ScopePolicy,
        audit: AuditLogger,
        timeout_seconds: float = 10.0,
        verify_tls: bool = True,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.35,
        max_redirects: int = 3,
        requests_per_second: float = 2.0,
        user_agent: str = "InternalSecurityFramework/0.2 (+security-team)",
        max_response_bytes: int = 2_000_000,
    ) -> None:
        self.scope = scope
        self.audit = audit
        self.timeout_seconds = timeout_seconds
        self.verify_tls = verify_tls
        self.max_redirects = max_redirects
        self.max_response_bytes = max_response_bytes
        self.rate_limiter = RateLimiter(requests_per_second)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "text/html,application/json,application/xml,text/plain,*/*;q=0.5",
            }
        )

        retry = Retry(
            total=max_retries,
            connect=max_retries,
            read=max_retries,
            status=max_retries,
            backoff_factor=retry_backoff_seconds,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "HEAD", "OPTIONS"),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if not verify_tls:
            self.audit.log({"event": "http_tls_verification_disabled", "severity": "warning"})

    @classmethod
    def from_config(cls, scope: ScopePolicy, audit: AuditLogger, config: object) -> "SafeHttpClient":
        return cls(
            scope=scope,
            audit=audit,
            timeout_seconds=float(getattr(config, "timeout_seconds", 10.0)),
            verify_tls=bool(getattr(config, "verify_tls", True)),
            max_retries=int(getattr(config, "max_retries", 2)),
            retry_backoff_seconds=float(getattr(config, "retry_backoff_seconds", 0.35)),
            max_redirects=int(getattr(config, "max_redirects", 3)),
            requests_per_second=float(getattr(config, "requests_per_second", 2.0)),
            user_agent=str(getattr(config, "user_agent", "InternalSecurityFramework/0.2 (+security-team)")),
            max_response_bytes=int(getattr(config, "max_response_bytes", 2_000_000)),
        )

    def get(self, url: str, **kwargs: object) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: object) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: object) -> requests.Response:
        method = method.upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError(f"SafeHttpClient only permits read-only HTTP methods, got {method}")

        request_id = uuid.uuid4().hex
        self._validate_or_audit_block(request_id, url)
        response = self._send_once(request_id, method, url, **kwargs)

        redirects = 0
        while response.is_redirect:
            if redirects >= self.max_redirects:
                self.audit.log(
                    {
                        "event": "http_redirect_limit_reached",
                        "request_id": request_id,
                        "url": response.url,
                        "max_redirects": self.max_redirects,
                    }
                )
                break
            location = response.headers.get("Location")
            if not location:
                break
            next_url = urljoin(response.url, location)
            try:
                self.scope.validate_redirect(response.url, next_url)
            except ScopeError as exc:
                self.audit.log(
                    {
                        "event": "http_redirect_blocked",
                        "request_id": request_id,
                        "source_url": response.url,
                        "redirect_url": next_url,
                        "reason": str(exc),
                    }
                )
                raise
            self.audit.log(
                {
                    "event": "http_redirect_followed",
                    "request_id": request_id,
                    "source_url": response.url,
                    "redirect_url": next_url,
                }
            )
            response = self._send_once(request_id, method, next_url, **kwargs)
            redirects += 1

        return response

    def _send_once(self, request_id: str, method: str, url: str, **kwargs: object) -> requests.Response:
        self.rate_limiter.wait()
        timeout = float(kwargs.pop("timeout", self.timeout_seconds))
        start = time.perf_counter()
        self.audit.log(
            {
                "event": "http_request",
                "request_id": request_id,
                "method": method,
                "url": url,
                "timeout_seconds": timeout,
                "verify_tls": self.verify_tls,
            }
        )
        try:
            response = self.session.request(
                method,
                url,
                timeout=timeout,
                verify=self.verify_tls,
                allow_redirects=False,
                stream=True,
                **kwargs,
            )
            self._enforce_response_size(response)
        except requests.RequestException as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.audit.log(
                {
                    "event": "http_error",
                    "request_id": request_id,
                    "url": url,
                    "elapsed_ms": round(elapsed_ms, 2),
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            raise

        elapsed_ms = (time.perf_counter() - start) * 1000
        self.audit.log(
            {
                "event": "http_response",
                "request_id": request_id,
                "url": response.url,
                "status": response.status_code,
                "elapsed_ms": round(elapsed_ms, 2),
                "bytes": len(response.content),
                "content_type": response.headers.get("content-type", ""),
            }
        )
        return response

    def _validate_or_audit_block(self, request_id: str, url: str) -> None:
        try:
            self.scope.validate_url(url)
        except ScopeError as exc:
            self.audit.log({"event": "http_request_blocked", "request_id": request_id, "url": url, "reason": str(exc)})
            raise

    def _enforce_response_size(self, response: requests.Response) -> None:
        content = bytearray()
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            content.extend(chunk)
            if len(content) > self.max_response_bytes:
                response.close()
                raise requests.RequestException(
                    f"response exceeded max_response_bytes={self.max_response_bytes}: {response.url}"
                )
        response._content = bytes(content)
        response._content_consumed = True
