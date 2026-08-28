from __future__ import annotations

import html
from pathlib import Path

from security_framework.core.engine import AssessmentResult


def write_html_report(result: AssessmentResult, path: Path) -> None:
    rows = []
    for finding in result.findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.id)}</td>"
            f"<td>{html.escape(finding.severity.value)}</td>"
            f"<td>{html.escape(finding.confidence.value)}</td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{html.escape(finding.asset)}</td>"
            "</tr>"
        )
    body = "\n".join(rows) or "<tr><td colspan='5'>No findings</td></tr>"
    doc = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Security Framework Report</title>
<style>body{{font-family:Arial,sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:.5rem}}th{{background:#f4f4f4}}</style></head>
<body><h1>Security Framework Report</h1><table><thead><tr><th>ID</th><th>Severity</th><th>Confidence</th><th>Title</th><th>Asset</th></tr></thead><tbody>{body}</tbody></table></body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
