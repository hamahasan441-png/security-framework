from __future__ import annotations

import json
from pathlib import Path

from security_framework.core.engine import AssessmentResult


def write_sarif_report(result: AssessmentResult, path: Path) -> None:
    rules = {}
    sarif_results = []
    for finding in result.findings:
        rule_id = finding.cwe or finding.title.lower().replace(" ", "-")[:80]
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description},
            "help": {"text": "\n".join(finding.remediation)},
        }
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": severity_to_sarif_level(finding.severity.value),
                "message": {"text": finding.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.asset}}}],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "security-framework", "rules": list(rules.values())}},
                "results": sarif_results,
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


def severity_to_sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
