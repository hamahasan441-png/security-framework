from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Evidence:
    kind: str
    description: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    title: str
    description: str
    asset: str
    severity: Severity
    confidence: Confidence
    remediation: list[str]
    evidence: list[Evidence] = field(default_factory=list)
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: "F-" + uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
