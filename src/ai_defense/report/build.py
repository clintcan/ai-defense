"""Assemble a :class:`Report` from engine outputs (scan + plan + preflight)."""

from __future__ import annotations

from ..scanner.scanner import HostFindings
from ..upgrade.preflight import OsUpgradeReport
from ..vuln.planner import RemediationItem
from .model import Report, ReportAsset, ReportFinding, ReportProvenance, severity_for


def _os_string(hf: HostFindings | None, pf: OsUpgradeReport | None) -> str | None:
    if pf is not None and pf.current_os:
        return pf.current_os
    if hf is not None and hf.os_release:
        osid = hf.os_release.get("ID")
        ver = hf.os_release.get("VERSION_ID")
        code = hf.os_release.get("VERSION_CODENAME")
        if osid and ver:
            return f"{osid} {ver} ({code})" if code else f"{osid} {ver}"
    return None


def _finding(item: RemediationItem) -> ReportFinding:
    return ReportFinding(
        cve_id=item.cve_id, package=item.package, kind=item.kind.value,
        severity=severity_for(item.cvss), cvss=item.cvss, kev=item.kev,
        installed_version=item.installed_version, fixed_version=item.fixed_version,
        priority=item.priority, source_ref=item.source_ref, note=item.note,
        requires_human=item.requires_human,
        unique_id=f"{item.asset_id}:{item.cve_id}:{item.package}",
    )


def build_report(
    inventory: list[HostFindings],
    plan_items: list[RemediationItem],
    preflight_reports: list[OsUpgradeReport],
    provenance: ReportProvenance,
    *,
    audit_verified: bool | None = None,
    connections: dict[str, dict] | None = None,
    exempt: dict[str, str] | None = None,
) -> Report:
    inv_by_id = {hf.asset_id: hf for hf in inventory}
    pf_by_id = {pf.asset_id: pf for pf in preflight_reports}
    conns = connections or {}
    exempt = exempt or {}

    items_by_asset: dict[str, list[RemediationItem]] = {}
    for it in plan_items:                          # plan is already prioritized
        items_by_asset.setdefault(it.asset_id, []).append(it)

    # One asset entry per scanned host, so a clean host still appears in the report.
    asset_ids = list(inv_by_id) or list(items_by_asset)
    for extra in items_by_asset:                   # include any asset only seen in the plan
        if extra not in asset_ids:
            asset_ids.append(extra)
    for aid in exempt:                             # include scan-exempt hosts (never scanned)
        if aid not in asset_ids:
            asset_ids.append(aid)

    assets: list[ReportAsset] = []
    for aid in asset_ids:
        hf = inv_by_id.get(aid)
        pf = pf_by_id.get(aid)
        conn = conns.get(aid) or {}
        assets.append(ReportAsset(
            asset_id=aid,
            host=conn.get("host"),
            port=conn.get("port"),
            os=_os_string(hf, pf),
            ecosystem=hf.ecosystem if hf else None,
            support_status=pf.support_status if pf else None,
            upgrade_verdict=pf.verdict.value if pf else None,
            upgrade_target=pf.target_version if pf else None,
            upgrade_path=list(pf.path) if pf else [],
            findings=[_finding(it) for it in items_by_asset.get(aid, [])],
            issues=list(hf.misconfigurations) if hf else [],
            scan_exempt=aid in exempt,
            exempt_reason=exempt.get(aid),
        ))

    return Report(provenance=provenance, assets=assets, audit_verified=audit_verified)
