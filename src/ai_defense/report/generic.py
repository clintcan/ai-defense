"""Serialize a :class:`Report` to this platform's documented, versioned JSON.

Schema (``schema_version`` 1.0) — self-describing and stable; see CLAUDE.md
"Reporting & export" for the field reference. Top-level shape:

    {
      "tool": "ai-defense",
      "schema_version": "1.0",
      "generated_at": "<ISO-8601 UTC>",
      "provenance": { scope, advisory_source, kev_enabled, scan_mode,
                      audit_verified },
      "summary": { assets, findings, by_kind{}, by_severity{}, kev,
                   eol_assets },
      "assets": [
        { "asset_id", "os", "ecosystem", "support_status",
          "upgrade": { "verdict", "target", "path" },
          "findings": [
            { "cve_id", "package", "kind", "severity", "cvss", "kev",
              "installed_version", "fixed_version", "priority",
              "requires_human", "source_ref", "reference_url", "note",
              "unique_id" } ] } ]
    }

Every finding carries ``reference_url`` so a human can verify it against the
advisory before approving a change, and ``unique_id`` (``asset:cve:package``) so
re-runs map onto the same finding over time.
"""

from __future__ import annotations

from .model import Report, ReportFinding


def _finding(f: ReportFinding) -> dict:
    return {
        "cve_id": f.cve_id, "package": f.package, "kind": f.kind,
        "severity": f.severity, "cvss": f.cvss, "kev": f.kev,
        "installed_version": f.installed_version, "fixed_version": f.fixed_version,
        "priority": f.priority, "requires_human": f.requires_human,
        "source_ref": f.source_ref, "reference_url": f.reference_url,
        "note": f.note, "unique_id": f.unique_id,
    }


def to_generic(report: Report) -> dict:
    p = report.provenance
    return {
        "tool": p.tool,
        "schema_version": p.schema_version,
        "generated_at": p.generated_at.isoformat(),
        "provenance": {
            "scope": list(p.scope),
            "advisory_source": p.advisory_source,
            "kev_enabled": p.kev_enabled,
            "scan_mode": p.scan_mode,
            "audit_verified": report.audit_verified,
        },
        "summary": {
            "assets": len(report.assets),
            "findings": len(report.all_findings),
            "by_kind": report.counts_by_kind(),
            "by_severity": report.counts_by_severity(),
            "kev": len(report.kev_findings),
            "eol_assets": [a.asset_id for a in report.eol_assets],
        },
        "assets": [
            {
                "asset_id": a.asset_id, "os": a.os, "ecosystem": a.ecosystem,
                "support_status": a.support_status,
                "upgrade": {"verdict": a.upgrade_verdict,
                            "target": a.upgrade_target, "path": a.upgrade_path},
                "findings": [_finding(f) for f in a.findings],
            }
            for a in report.assets
        ],
    }
