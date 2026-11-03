"""Serialize a :class:`Report` to DefectDojo's Generic Findings Import (JSON).

Produces ``{"findings": [...]}`` that DefectDojo's *Generic Findings Import*
parser ingests directly. Mapping (see CLAUDE.md "Reporting & export"):

  asset_id            -> endpoints[]            (DefectDojo Endpoint = the host)
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
    lines = [f.note, "", f"Host: {asset.asset_id}"]
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


def _tags(f: ReportFinding) -> list[str]:
    tags = ["ai-defense", f.kind]
    if f.kev:
        tags.append("kev")
    if f.requires_human:
        tags.append("needs-approval")
    return tags


def _finding(f: ReportFinding, asset: ReportAsset, date: str) -> dict:
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
        "tags": _tags(f),
        "endpoints": [asset.asset_id],
    }
    if f.cvss is not None:
        out["cvssv3_score"] = f.cvss
    if f.reference_url:
        out["references"] = f.reference_url
    return out


def to_defectdojo(report: Report) -> dict:
    date = report.provenance.generated_at.date().isoformat()
    findings = [
        _finding(f, a, date)
        for a in report.assets
        for f in a.findings
    ]
    return {"findings": findings}
