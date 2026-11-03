"""Markdown renderers: an executive summary and a technical report.

Both are deterministic pure functions returning a string, so they are trivially
testable and diff-able. The executive summary is plain-language posture for
decision-makers (no IPs, no package noise); the technical report is per-host
detail an operator can verify against each cited advisory before approving.
"""

from __future__ import annotations

from .model import Report, ReportAsset, ReportFinding

_KIND_LABEL = {"patch": "Patch now", "mitigation": "Mitigate (no patch yet)",
               "escalate": "Escalate (no fix)"}


def _provenance_line(report: Report) -> str:
    p = report.provenance
    bits = [f"Generated {p.generated_at.isoformat()}",
            f"tool `{p.tool}`",
            f"advisories: {p.advisory_source}",
            f"KEV: {'on' if p.kev_enabled else 'off'}",
            f"scan: {p.scan_mode}"]
    if report.audit_verified is not None:
        bits.append(f"audit chain: {'verified' if report.audit_verified else 'FAILED'}")
    return " · ".join(bits)


# --- executive summary ---------------------------------------------------

def executive_summary_md(report: Report) -> str:
    by_kind = report.counts_by_kind()
    by_sev = report.counts_by_severity()
    kev = report.kev_findings
    eol = report.eol_assets

    out: list[str] = []
    out.append("# Vulnerability Posture — Executive Summary")
    out.append("")
    out.append(f"_{_provenance_line(report)}_")
    out.append("")
    out.append(f"**{len(report.assets)}** asset(s) assessed · "
               f"**{len(report.all_findings)}** open finding(s).")
    out.append("")

    # Headline risk.
    out.append("## At a glance")
    out.append("")
    out.append(f"- **Actively exploited (CISA KEV): {len(kev)}** — "
               + (", ".join(sorted({f.cve_id for f in kev})) if kev
                  else "none detected") + ".")
    out.append(f"- **Patch available now:** {by_kind.get('patch', 0)} finding(s).")
    out.append(f"- **No vendor fix (needs mitigation/decision):** "
               f"{by_kind.get('mitigation', 0) + by_kind.get('escalate', 0)} finding(s).")
    if by_sev:
        out.append("- **By severity:** "
                   + ", ".join(f"{k} {v}" for k, v in by_sev.items()) + ".")
    if eol:
        out.append(f"- **End-of-life / ESM OS: {len(eol)} host(s)** — "
                   + ", ".join(f"{a.asset_id} ({a.os}, {a.support_status})" for a in eol)
                   + ". These need an OS upgrade; many findings cannot be patched in place.")
    out.append("")

    # Top risks.
    top = _top_findings(report, limit=10)
    if top:
        out.append("## Top risks")
        out.append("")
        out.append("| CVE | Host | Package | Severity | KEV | Action |")
        out.append("|---|---|---|---|---|---|")
        for a, f in top:
            out.append(f"| {f.cve_id} | {a.asset_id} | {f.package} | "
                       f"{f.severity}{_cvss(f)} | {'yes' if f.kev else ''} | "
                       f"{_KIND_LABEL.get(f.kind, f.kind)} |")
        out.append("")

    # Recommended actions (numbered in priority order).
    out.append("## Recommended actions")
    out.append("")
    actions: list[str] = []
    if kev:
        actions.append("**Immediately** remediate the actively-exploited (KEV) findings "
                       "above — these are being exploited in the wild.")
    if by_kind.get("patch"):
        actions.append(f"Schedule the {by_kind['patch']} patchable finding(s) through the "
                       "approval gate (canary first, then fleet).")
    if eol:
        actions.append("Plan OS upgrades for the end-of-life/ESM host(s); run "
                       "`upgrade_preflight` for the supported path and readiness.")
    if actions:
        out.extend(f"{i}. {text}" for i, text in enumerate(actions, start=1))
    else:
        out.append("- No urgent action: no KEV findings, patches, or EOL hosts detected "
                   "in this scope.")
    out.append("")
    out.append("_This report is read-only intelligence. No change has been made; every "
               "remediation goes through the human approval gate._")
    out.append("")
    return "\n".join(out)


# --- technical report ----------------------------------------------------

def technical_report_md(report: Report) -> str:
    out: list[str] = []
    out.append("# Vulnerability Technical Report")
    out.append("")
    out.append(f"_{_provenance_line(report)}_")
    out.append("")
    out.append(f"Scope: {', '.join(report.provenance.scope) or '(none)'}")
    out.append("")

    for a in report.assets:
        out.extend(_asset_section(a))
    out.append("---")
    out.append("")
    out.append("Every finding cites a source URL; verify it against the advisory before "
               "approving any change. Package versions reflect the authenticated scan at "
               "generation time.")
    out.append("")
    return "\n".join(out)


def _asset_section(a: ReportAsset) -> list[str]:
    out = [f"## {a.asset_id}", ""]
    meta = []
    if a.os:
        meta.append(f"**OS:** {a.os}")
    if a.support_status:
        meta.append(f"**Support:** {a.support_status}")
    if a.ecosystem:
        meta.append(f"**Ecosystem:** {a.ecosystem}")
    if meta:
        out.append(" · ".join(meta))
        out.append("")
    if a.upgrade_verdict:
        line = f"**Upgrade preflight:** {a.upgrade_verdict}"
        if a.upgrade_target:
            line += f" → target {a.upgrade_target}"
        if a.upgrade_path:
            line += f" (path: {' → '.join(a.upgrade_path)})"
        out.append(line)
        out.append("")

    if not a.findings:
        out.append("_No open findings._")
        out.append("")
        return out

    out.append("| CVE | Package | Installed → Fixed | CVSS | KEV | Action | Source |")
    out.append("|---|---|---|---|---|---|---|")
    for f in a.findings:
        ver = _version_cell(f)
        src = f"[link]({f.reference_url})" if f.reference_url else f.source_ref
        out.append(f"| {f.cve_id} | {f.package} | {ver} | "
                   f"{'' if f.cvss is None else f.cvss} | {'yes' if f.kev else ''} | "
                   f"{_KIND_LABEL.get(f.kind, f.kind)} | {src} |")
    out.append("")
    return out


# --- helpers -------------------------------------------------------------

def _cvss(f: ReportFinding) -> str:
    return f" ({f.cvss})" if f.cvss is not None else ""


def _version_cell(f: ReportFinding) -> str:
    installed = f.installed_version or "?"
    if f.fixed_version:
        return f"{installed} → {f.fixed_version}"
    return f"{installed} → (no fix)"


def _top_findings(report: Report, *, limit: int) -> list[tuple[ReportAsset, ReportFinding]]:
    pairs = [(a, f) for a in report.assets for f in a.findings]
    pairs.sort(key=lambda af: af[1].priority, reverse=True)
    return pairs[:limit]
