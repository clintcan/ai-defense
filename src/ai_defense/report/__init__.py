"""Reporting & export (read-only presentation layer).

Turns the engine's already-redacted results (plan, preflight, scan, audit) into
human and machine deliverables:

  * ``executive-summary.md`` — risk posture for decision-makers,
  * ``technical-report.md``  — per-host detail with source citations,
  * ``findings.generic.json`` — this platform's documented, versioned schema,
  * ``findings.defectdojo.json`` — DefectDojo Generic Findings Import format.

It never reaches a host or a secret: it consumes results the toolset already
produced and redacted. All output is written to local files — a vulnerability
inventory of your own fleet is exactly what this platform must not leak to an
external service, so nothing here publishes anywhere.
"""

from .build import build_report
from .model import Report, ReportAsset, ReportFinding, ReportProvenance, severity_for
from .writer import REPORT_FILES, write_report

__all__ = ["Report", "ReportAsset", "ReportFinding", "ReportProvenance",
           "severity_for", "build_report", "write_report", "REPORT_FILES"]
