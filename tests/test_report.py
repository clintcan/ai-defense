"""Reporting & export: model, build, serializers (generic + DefectDojo),
markdown, the file writer, and engine/MCP wiring."""

import json
import os
from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_demo_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.report import ReportProvenance, write_report
from ai_defense.report.defectdojo import to_defectdojo
from ai_defense.report.generic import to_generic
from ai_defense.report.markdown import executive_summary_md, technical_report_md
from ai_defense.report.model import (
    Report,
    ReportAsset,
    ReportFinding,
    severity_for,
)

# --- model helpers -------------------------------------------------------

def test_severity_bands():
    assert severity_for(9.8) == "Critical"
    assert severity_for(7.5) == "High"
    assert severity_for(5.0) == "Medium"
    assert severity_for(2.0) == "Low"
    assert severity_for(0.0) == "Info"
    assert severity_for(None) == "Unknown"       # missing score != low risk


def _finding(cve="CVE-2021-4034", kev=True, cvss=7.8, kind="patch"):
    return ReportFinding(
        cve_id=cve, package="policykit-1", kind=kind, severity=severity_for(cvss),
        cvss=cvss, kev=kev, installed_version="0.105-20", fixed_version="0.105-20ubuntu0.1",
        priority=1078.0, source_ref=cve, note="Upgrade policykit-1.",
        requires_human=(kind != "patch"), unique_id=f"h1:{cve}:policykit-1")


def _report(findings=None, *, support="esm"):
    prov = ReportProvenance(
        generated_at=datetime(2026, 11, 4, 12, 0, 0),
        scope=["h1"], advisory_source="osv.dev", kev_enabled=True)
    asset = ReportAsset(asset_id="h1", host="203.0.113.136", port=22,
                        os="ubuntu 18.04 (bionic)", ecosystem="Ubuntu:18.04:LTS",
                        support_status=support, upgrade_verdict="ready",
                        upgrade_target="20.04", upgrade_path=["20.04", "22.04", "24.04"],
                        findings=findings if findings is not None else [_finding()])
    return Report(provenance=prov, assets=[asset], audit_verified=True)


def test_reference_url_maps_cve_and_distro():
    assert _finding(cve="CVE-2021-4034").reference_url.endswith("/CVE-2021-4034")
    assert "ubuntu.com/security/USN-1-1" in _finding(cve="USN-1-1").reference_url
    assert _finding(cve="GHSA-x").reference_url is None


def test_report_aggregates():
    r = _report([_finding("CVE-1", kev=True, cvss=9.8),
                 _finding("CVE-2", kev=False, cvss=5.0, kind="mitigation")])
    assert r.counts_by_kind() == {"patch": 1, "mitigation": 1}
    assert r.counts_by_severity() == {"Critical": 1, "Medium": 1}
    assert [f.cve_id for f in r.kev_findings] == ["CVE-1"]
    assert [a.asset_id for a in r.eol_assets] == ["h1"]


# --- generic JSON --------------------------------------------------------

def test_generic_json_schema():
    doc = to_generic(_report())
    assert doc["tool"] == "ai-defense" and doc["schema_version"] == "1.0"
    assert doc["provenance"]["kev_enabled"] is True
    assert doc["summary"]["kev"] == 1 and doc["summary"]["eol_assets"] == ["h1"]
    a = doc["assets"][0]
    assert a["host"] == "203.0.113.136" and a["port"] == 22
    assert a["upgrade"]["target"] == "20.04"
    f = a["findings"][0]
    assert f["cve_id"] == "CVE-2021-4034" and f["kev"] is True
    assert f["reference_url"].endswith("/CVE-2021-4034")
    assert f["unique_id"] == "h1:CVE-2021-4034:policykit-1"


# --- DefectDojo ----------------------------------------------------------

def test_defectdojo_import_shape():
    doc = to_defectdojo(_report())
    assert list(doc.keys()) == ["findings"]
    f = doc["findings"][0]
    assert f["endpoints"] == ["203.0.113.136:22"]        # real IP:port, not the name
    assert f["vulnerability_ids"] == ["CVE-2021-4034"]
    assert f["unique_id_from_tool"] == "h1:CVE-2021-4034:policykit-1"
    assert f["cvssv3_score"] == 7.8
    assert "kev" in f["tags"] and "patch" in f["tags"]
    assert f["active"] is True and f["verified"] is True
    assert f["references"].endswith("/CVE-2021-4034")


def test_defectdojo_kev_floors_severity_to_high():
    # a low-CVSS but actively-exploited finding must not import as Low/Info
    doc = to_defectdojo(_report([_finding(cve="CVE-9", kev=True, cvss=3.0)]))
    assert doc["findings"][0]["severity"] == "High"


def test_defectdojo_noncve_id_omits_vulnerability_ids():
    doc = to_defectdojo(_report([_finding(cve="USN-1234-1", kev=False, cvss=5.0)]))
    f = doc["findings"][0]
    assert f["vulnerability_ids"] == [] and f["vuln_id_from_tool"] == "USN-1234-1"


# --- markdown ------------------------------------------------------------

def test_executive_summary_highlights_kev_and_eol():
    md = executive_summary_md(_report())
    assert "Executive Summary" in md
    assert "CVE-2021-4034" in md                          # KEV cve called out
    assert "End-of-life" in md or "ESM" in md
    assert "approval gate" in md


def test_technical_report_has_per_asset_table():
    md = technical_report_md(_report())
    assert "## h1" in md
    assert "203.0.113.136" in md                          # IP address shown
    assert "ubuntu 18.04 (bionic)" in md
    assert "0.105-20 → 0.105-20ubuntu0.1" in md           # installed -> fixed
    assert "nvd.nist.gov" in md                            # source link


# --- file writer ---------------------------------------------------------

def test_write_report_emits_four_files(tmp_path):
    paths = write_report(_report(), str(tmp_path))
    assert set(paths) == {"executive_summary", "technical_report",
                          "generic_json", "defectdojo_json"}
    for p in paths.values():
        assert (tmp_path / os.path.basename(p)).exists()
    # both JSON files parse and have the expected roots
    generic = json.loads((tmp_path / "findings.generic.json").read_text(encoding="utf-8"))
    dd = json.loads((tmp_path / "findings.defectdojo.json").read_text(encoding="utf-8"))
    assert generic["schema_version"] == "1.0"
    assert "findings" in dd


# --- engine + MCP --------------------------------------------------------

def test_engine_report_on_demo(tmp_path):
    eng = build_demo_engine()
    report, paths = eng.report(["any-host"], out_dir=str(tmp_path))
    # demo: ubuntu 18.04 host, openssl patch (KEV) + bash mitigation
    assert report.counts_by_kind().get("patch") == 1
    assert report.counts_by_kind().get("mitigation") == 1
    assert len(report.kev_findings) == 1
    assert report.provenance.scan_mode == "simulated"     # demo inspector
    assert all(os.path.exists(p) for p in paths.values())


def test_engine_report_threads_registry_host():
    eng = build_demo_engine()
    now = datetime.now(UTC)
    eng.registry.register(Asset(
        "vps-9", "ssh-host", "ops", "prod",
        Authorization("sig", "op", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="203.0.113.9", key_ref="ssh-key/x", port=2222)))
    a = eng.build_report(["vps-9"]).assets[0]
    assert a.host == "203.0.113.9" and a.port == 2222


def test_build_report_populates_asset_os_and_preflight():
    eng = build_demo_engine()
    report = eng.build_report(["any-host"])
    a = report.assets[0]
    assert a.os.startswith("ubuntu 18.04")
    assert a.support_status == "esm" and a.upgrade_target == "20.04"


def test_mcp_report_returns_paths_and_summary(tmp_path):
    eng = build_demo_engine()
    out = handle_call(eng, "report", {"asset_ids": ["any-host"], "out_dir": str(tmp_path)})
    assert set(out["files"]) == {"executive_summary", "technical_report",
                                 "generic_json", "defectdojo_json"}
    assert out["summary"]["kev"] == 1
    assert out["summary"]["by_kind"]["patch"] == 1
    assert os.path.isdir(out["out_dir"])
