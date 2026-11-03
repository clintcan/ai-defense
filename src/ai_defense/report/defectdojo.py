"""Serialize a :class:`Report` to DefectDojo's Generic Findings Import (JSON).

Produces ``{"findings": [...]}`` that DefectDojo's *Generic Findings Import*
parser ingests directly. Mapping (see CLAUDE.md "Reporting & export"):

  host (else asset)   -> endpoints[]            (DefectDojo Endpoint = IP:port)
  cve_id (canonical)  -> vulnerability_ids[]    (DefectDojo enriches EPSS/KEV)
  cvss                -> cvssv3_score
  severity band       -> severity               (Critical/High/Medium/Low/Info)
  kev                 -> tags:["kev"]           + severity floor of High
  installed/fixed     -> component_name/version + mitigation
  source_ref          -> references (URL)
  unique_id           -> unique_id_from_tool    (reimport closes fixed findings)
  kind                -> tags:[kind]

``active`` is True (all reported findings are open) and ``verified`` is True
(observed on the host by an authenticated scan, not inferred).

When the advisory feed degraded for this run (``provenance.feed_degraded``),
every finding is additionally tagged ``scan-degraded``: the scan was incomplete,
so a reimport must run with auto-close **disabled** — otherwise DefectDojo would
close real findings this partial scan never saw (CLAUDE.md §8, hard rule #7).
"""

from __future__ import annotations

from .model import Report, ReportAsset, ReportFinding

# DefectDojo accepts these severities; "Unknown"/"Info" are normalized to Info.
_DD_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def _severity(f: ReportFinding) -> str:
    sev = f.severity if f.severity in _DD_SEVERITIES else "Info"
    if f.kev and sev in ("Info", "Low", "Medium"):
        return "High"           # actively exploited is never low-priority in DD
    return sev


def _title(f: ReportFinding) -> str:
    return f"{f.cve_id} in {f.package}"


def _description(f: ReportFinding, asset: ReportAsset) -> str:
    host_line = f"Host: {asset.asset_id}" + (f" ({asset.host})" if asset.host else "")
    lines = [f.note, "", host_line]
    if asset.os:
        lines.append(f"OS: {asset.os}"
                     + (f" ({asset.support_status})" if asset.support_status else ""))
    if f.installed_version:
        lines.append(f"Installed: {f.package} {f.installed_version}")
    if f.kev:
        lines.append("CISA KEV: actively exploited in the wild.")
    return "\n".join(lines)


def _mitigation(f: ReportFinding) -> str:
    if f.kind == "patch" and f.fixed_version:
        return f"Upgrade {f.package} to {f.fixed_version} or later."
    if f.kind == "escalate":
        return ("No vendor fix available for this release — escalate for a human "
                "decision (an OS upgrade may be required).")
    return f.note


def _endpoint(asset: ReportAsset) -> str:
    if asset.host:
        return f"{asset.host}:{asset.port}" if asset.port else asset.host
    return asset.asset_id


def _tags(f: ReportFinding, *, degraded: bool = False) -> list[str]:
    tags = ["ai-defense", f.kind]
    if f.kev:
        tags.append("kev")
    if f.requires_human:
        tags.append("needs-approval")
    if degraded:
        # This finding came from an incomplete scan; the importer must not
        # auto-close findings absent from a degraded run (CLAUDE.md §8).
        tags.append("scan-degraded")
    return tags


def _finding(f: ReportFinding, asset: ReportAsset, date: str,
             *, degraded: bool = False) -> dict:
    out = {
        "title": _title(f),
        "description": _description(f, asset),
        "severity": _severity(f),
        "date": date,
        "mitigation": _mitigation(f),
        "vulnerability_ids": [f.cve_id] if f.cve_id.startswith("CVE-") else [],
        "vuln_id_from_tool": f.cve_id,
        "unique_id_from_tool": f.unique_id,
        "component_name": f.package,
        "component_version": f.installed_version,
        "active": True,
        "verified": True,
        "tags": _tags(f, degraded=degraded),
        # DefectDojo Endpoint = the real address when known, else the asset name.
        "endpoints": [_endpoint(asset)],
    }
    if f.cvss is not None:
        out["cvssv3_score"] = f.cvss
    if f.reference_url:
        out["references"] = f.reference_url
    return out


def to_defectdojo(report: Report) -> dict:
    date = report.provenance.generated_at.date().isoformat()
    degraded = report.provenance.feed_degraded
    findings = [
        _finding(f, a, date, degraded=degraded)
        for a in report.assets
        for f in a.findings
    ]
    return {"findings": findings}
