from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security_framework.core.redaction import redact


@dataclass
class AuditLogger:
    path: Path | None = None

    def log(self, event: dict[str, Any]) -> None:
        safe_event: dict[str, Any] = {key: redact(value) for key, value in event.items()}
        safe_event["timestamp"] = time.time()
        body = json.dumps(safe_event, sort_keys=True, ensure_ascii=False)
        safe_event["event_hash"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
        line = json.dumps(safe_event, sort_keys=True, ensure_ascii=False)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        else:
            print(line)
