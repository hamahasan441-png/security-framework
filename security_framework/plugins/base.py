from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from security_framework.core.http_client import SafeHttpClient
from security_framework.findings import Finding


@dataclass(frozen=True)
class CheckContext:
    target_url: str
    http: SafeHttpClient


class SecurityCheck(ABC):
    id: str = "base"
    name: str = "Base security check"
    description: str = "Base class for defensive checks"

    @abstractmethod
    def run(self, context: CheckContext) -> list[Finding]:
        raise NotImplementedError
