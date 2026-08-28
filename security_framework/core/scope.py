from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlparse


DEFAULT_BLOCKED_CIDRS = (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "fe80::/10",
    "ff00::/8",
)
PRIVATE_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
)
ALLOWED_SCHEMES = {"http", "https"}


class ScopeError(ValueError):
    """Raised when a target, redirect, host, or IP violates scan scope."""


@dataclass(frozen=True)
class ScopePolicy:
    """Hard boundary for all framework network operations.

    No HTTP client, crawler, or plugin should open a connection until this policy
    has approved the target URL. Hostnames are resolved and every returned IP is
    checked to reduce accidental SSRF, localhost, link-local, and out-of-scope
    traffic.
    """

    allowed_domains: set[str] = field(default_factory=set)
    allowed_cidrs: set[str] = field(default_factory=set)
    allow_private_ranges: bool = False
    allow_redirects: bool = True
    blocked_cidrs: tuple[str, ...] = DEFAULT_BLOCKED_CIDRS

    @classmethod
    def from_config(cls, config: object) -> "ScopePolicy":
        return cls(
            allowed_domains=set(getattr(config, "allowed_domains", []) or []),
            allowed_cidrs=set(getattr(config, "allowed_cidrs", []) or []),
            allow_private_ranges=bool(getattr(config, "allow_private_ranges", False)),
            allow_redirects=bool(getattr(config, "allow_redirects", True)),
        )

    def validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ALLOWED_SCHEMES:
            raise ScopeError(f"blocked unsupported URL scheme: {parsed.scheme!r}")
        if parsed.username or parsed.password:
            raise ScopeError("blocked URL with embedded credentials")
        if not parsed.hostname:
            raise ScopeError("blocked URL with no hostname")
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise ScopeError(f"blocked invalid port: {parsed.port}")
        self.validate_host(parsed.hostname)

    def validate_redirect(self, source_url: str, redirect_url: str) -> None:
        if not self.allow_redirects:
            raise ScopeError("redirects are disabled by scope policy")
        source = urlparse(source_url)
        dest = urlparse(redirect_url)
        if dest.scheme.lower() not in ALLOWED_SCHEMES:
            raise ScopeError(f"blocked redirect to unsupported scheme: {dest.scheme!r}")
        if source.scheme.lower() == "https" and dest.scheme.lower() == "http":
            raise ScopeError("blocked HTTPS-to-HTTP redirect downgrade")
        self.validate_url(redirect_url)

    def validate_host(self, host: str) -> None:
        normalized = normalize_hostname(host)
        if self.allowed_domains and not self._domain_allowed(normalized):
            raise ScopeError(f"host is outside allowed domains: {host}")
        for ip in resolve_host(normalized):
            self.validate_ip(ip)

    def validate_ip(self, ip: str) -> None:
        ip_obj = ipaddress.ip_address(ip)
        blocked_networks = [ipaddress.ip_network(cidr) for cidr in self.blocked_cidrs]
        if any(ip_obj in network for network in blocked_networks):
            raise ScopeError(f"IP is in blocked range: {ip}")

        private_networks = [ipaddress.ip_network(cidr) for cidr in PRIVATE_CIDRS]
        if not self.allow_private_ranges and any(ip_obj in network for network in private_networks):
            raise ScopeError(f"private IP blocked by policy: {ip}")

        if self.allowed_cidrs:
            allowed_networks = [ipaddress.ip_network(cidr, strict=False) for cidr in self.allowed_cidrs]
            if not any(ip_obj in network for network in allowed_networks):
                raise ScopeError(f"IP is outside allowed CIDRs: {ip}")

    def _domain_allowed(self, host: str) -> bool:
        allowed = {normalize_hostname(domain) for domain in self.allowed_domains}
        return any(host == domain or host.endswith("." + domain) for domain in allowed)


def normalize_hostname(host: str) -> str:
    hostname = host.strip().lower().strip(".")
    if not hostname:
        raise ScopeError("empty hostname")
    # IDNA normalization makes Unicode domains compare consistently.
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"invalid hostname: {host}") from exc


@lru_cache(maxsize=4096)
def resolve_host(host: str) -> frozenset[str]:
    """Resolve host and return all A/AAAA addresses as strings."""
    try:
        # IP literals do not need DNS and are validated directly.
        ipaddress.ip_address(host)
        return frozenset({host})
    except ValueError:
        pass

    try:
        records = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"could not resolve host: {host}") from exc

    addresses = frozenset(str(item[4][0]) for item in records)
    if not addresses:
        raise ScopeError(f"host resolved to no addresses: {host}")
    return addresses
