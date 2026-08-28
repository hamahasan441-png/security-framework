from __future__ import annotations

import json
from pathlib import Path

from security_framework.core.engine import AssessmentResult


def write_json_report(result: AssessmentResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
