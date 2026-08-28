from __future__ import annotations

import re

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in [
        r"(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-]+",
        r"(api[_-]?key\s*[:=]\s*)['\"]?[A-Za-z0-9_\-]{16,}",
        r"(password\s*[:=]\s*)['\"]?[^'\"\s]+",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    ]
)


def redact(value: object) -> str:
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(lambda m: (m.group(1) if m.groups() else "") + "[REDACTED]", text)
    return text
