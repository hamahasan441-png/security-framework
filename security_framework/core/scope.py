from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


DEFAULT_BLOCKED_CIDRS = (
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "::1/128",
    "fe80::/10",
)
PRIVATE_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class ScopePolicy:
    allowed_domains: set[str] = field(default_factory=set)
    allowed_cidrs: set[str] = field(default_factory=set)
    allow_private_ranges: bool = False
    blocked_cidrs: tuple[str, ...] = DEFAULT_BLOCKED_CIDRS

    def validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ScopeError(f"Blocked unsupported URL scheme: {parsed.scheme}")
        if not parsed.hostname:
            raise ScopeError("URL has no hostname")
        self.validate_host(parsed.hostname)

    def validate_host(self, host: str) -> None:
        normalized = host.lower().strip(".")
        if self.allowed_domains and not any(
            normalized == d or normalized.endswith("." + d) for d in self.allowed_domains
        ):
            raise ScopeError(f"Host is outside allowed domains: {host}")
        for ip in resolve_host(normalized):
            self.validate_ip(ip)

    def validate_ip(self, ip: str) -> None:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in self.blocked_cidrs:
            if ip_obj in ipaddress.ip_network(cidr):
                raise ScopeError(f"IP is in blocked range: {ip}")
        if not self.allow_private_ranges:
            for cidr in PRIVATE_CIDRS:
                if ip_obj in ipaddress.ip_network(cidr):
                    raise ScopeError(f"Private IP blocked by policy: {ip}")
        if self.allowed_cidrs:
            if not any(ip_obj in ipaddress.ip_network(cidr) for cidr in self.allowed_cidrs):
                raise ScopeError(f"IP is outside allowed CIDRs: {ip}")


def resolve_host(host: str) -> set[str]:
    try:
        return {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise ScopeError(f"Could not resolve host: {host}") from exc
