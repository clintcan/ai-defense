"""Write a :class:`Report` to local files (all four deliverables).

Returns a map of logical name -> absolute path. Output is local-only by design:
a report is a vulnerability inventory of the operator's own fleet and must not
leave their infrastructure.
"""

from __future__ import annotations

import json
import os

from .defectdojo import to_defectdojo
from .generic import to_generic
from .markdown import executive_summary_md, technical_report_md
from .model import Report

REPORT_FILES = {
    "executive_summary": "executive-summary.md",
    "technical_report": "technical-report.md",
    "generic_json": "findings.generic.json",
    "defectdojo_json": "findings.defectdojo.json",
}


def write_report(report: Report, out_dir: str) -> dict[str, str]:
    """Write all four deliverables into ``out_dir`` (created if missing)."""
    os.makedirs(out_dir, exist_ok=True)
    payloads: dict[str, str] = {
        "executive_summary": executive_summary_md(report),
        "technical_report": technical_report_md(report),
        "generic_json": json.dumps(to_generic(report), indent=2, sort_keys=False),
        "defectdojo_json": json.dumps(to_defectdojo(report), indent=2, sort_keys=False),
    }
    paths: dict[str, str] = {}
    for key, filename in REPORT_FILES.items():
        path = os.path.join(out_dir, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(payloads[key])
        paths[key] = os.path.abspath(path)
    return paths
