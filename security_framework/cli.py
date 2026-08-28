from __future__ import annotations

import argparse
from pathlib import Path

from security_framework.core.config import Config
from security_framework.core.engine import AssessmentEngine
from security_framework.reporting.json_report import write_json_report
from security_framework.reporting.html_report import write_html_report
from security_framework.reporting.sarif_report import write_sarif_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe defensive security assessment framework")
    parser.add_argument("--config", required=True, help="Path to YAML config")
    parser.add_argument("--out", default="reports", help="Output directory")
    args = parser.parse_args()

    config = Config.from_yaml(Path(args.config))
    engine = AssessmentEngine(config)
    result = engine.run()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json_report(result, out_dir / "report.json")
    write_html_report(result, out_dir / "report.html")
    write_sarif_report(result, out_dir / "report.sarif.json")
    print(f"Wrote reports to {out_dir}")
    return 0
