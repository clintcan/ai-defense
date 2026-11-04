"""Scan-exempt assets: hosts intentionally not SSH-reachable are skipped by the
scan/report path and shown as *exempt*, never counted as failures."""

from datetime import UTC, datetime, timedelta

import pytest

from ai_defense.composition import build_engine
from ai_defense.db import init_db
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, AssetRegistry, Authorization, ConnectionInfo
from ai_defense.report.generic import to_generic
from ai_defense.report.markdown import executive_summary_md, technical_report_md
from ai_defense.report.model import Report, ReportAsset, ReportProvenance


def _ssh_asset(asset_id="vps-1") -> Asset:
    now = datetime.now(UTC)
    return Asset(
        asset_id, "ssh-host", "ops", "prod",
        Authorization("sig", "operator", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01",
                                  port=22, user="ubuntu"))


# --- registry (in-memory) & repository (DB) -----------------------------

def test_registry_set_scan_exempt_preserves_auth_and_connection():
    reg = AssetRegistry()
    reg.register(_ssh_asset("m-1"))
    before = reg.get("m-1").authorization
    a = reg.set_scan_exempt("m-1", True, "no SSH by design")
    assert a.attributes["scan_exempt"] is True
    assert a.attributes["scan_exempt_reason"] == "no SSH by design"
    assert a.authorization == before                       # attestation untouched
    assert a.connection.key_ref == "ssh-key/vps-demo-01"   # connection untouched
    cleared = reg.set_scan_exempt("m-1", False)
    assert "scan_exempt" not in cleared.attributes


def test_repo_set_and_clear_scan_exempt():
    from ai_defense.db.repositories import AssetRepository

    repo = AssetRepository(init_db())
    repo.save(_ssh_asset("db-1"))
    a = repo.set_scan_exempt("db-1", True, "no ssh")
    assert a.attributes.get("scan_exempt") is True
    assert a.attributes["scan_exempt_reason"] == "no ssh"
    assert a.connection.host == "1.1.1.1"                  # connection preserved
    assert repo.get("db-1").attributes.get("scan_exempt") is True   # persisted
    repo.set_scan_exempt("db-1", False)
    assert repo.get("db-1").attributes.get("scan_exempt") is None
    with pytest.raises(KeyError):
        repo.set_scan_exempt("ghost", True)


# --- report model -------------------------------------------------------

def _mixed_report() -> Report:
    prov = ReportProvenance(generated_at=datetime(2026, 11, 4), scope=["a", "b", "c"],
                            advisory_source="osv.dev", kev_enabled=True)
    scanned = ReportAsset("a", host="1.1.1.1", os="ubuntu 22.04 (jammy)")
    failed = ReportAsset("b", host="2.2.2.2",
                         issues=["scan failed: TimeoutError — unreachable on :22"])
    exempt = ReportAsset("c", host="3.3.3.3", scan_exempt=True, exempt_reason="off-limits")
    return Report(provenance=prov, assets=[scanned, failed, exempt])


def test_exempt_is_not_a_failure():
    r = _mixed_report()
    assert [a.asset_id for a in r.failed_assets] == ["b"]      # exempt not here
    assert [a.asset_id for a in r.exempt_assets] == ["c"]
    c = r.assets[2]
    assert c.scan_exempt and not c.scanned and not c.failed


def test_exec_summary_separates_exempt_from_failed():
    md = executive_summary_md(_mixed_report())
    assert "**1** of **3** asset(s) scanned" in md            # only 'a' scanned
    # distinct callouts; check by unique IPs (asset ids 'b'/'c' collide with words)
    failure_line = next(line for line in md.splitlines() if "could not be scanned" in line)
    exempt_line = next(line for line in md.splitlines() if "exempt by configuration" in line)
    assert "2.2.2.2" in failure_line and "3.3.3.3" not in failure_line   # only the real failure
    assert "3.3.3.3" in exempt_line and "2.2.2.2" not in exempt_line     # only the exempt host


def test_technical_report_marks_exempt():
    tr = technical_report_md(_mixed_report())
    assert "## c" in tr and "exempt by configuration" in tr and "off-limits" in tr


def test_generic_json_reports_exempt():
    g = to_generic(_mixed_report())
    assert g["summary"]["exempt_assets"] == ["c"]
    assert g["summary"]["failed_assets"] == ["b"]
    assert g["assets"][2]["scan_exempt"] is True
    assert g["assets"][2]["exempt_reason"] == "off-limits"
    assert g["assets"][2]["scanned"] is False


# --- engine: exempt hosts are never scanned -----------------------------

class _SpyInspector:
    """Records which assets collect() was called for."""

    def __init__(self):
        self.collected: list[str] = []

    def collect(self, asset_id):
        self.collected.append(asset_id)
        return {"installed_packages": {"openssl": "3.0.5"},
                "os_release": {"ID": "ubuntu", "VERSION_ID": "22.04"}}


def test_engine_skips_scanning_exempt_hosts():
    spy = _SpyInspector()
    eng = build_engine(inspector=spy)                 # in-memory registry, custom inspector
    eng.registry.register(_ssh_asset("web-1"))
    eng.registry.register(_ssh_asset("web-2"))
    eng.registry.set_scan_exempt("web-2", True, "off-limits")

    report = eng.build_report(["web-1", "web-2"])
    assert spy.collected == ["web-1"]                 # web-2 never touched
    by_id = {a.asset_id: a for a in report.assets}
    assert by_id["web-1"].scanned is True
    assert by_id["web-2"].scan_exempt is True and not by_id["web-2"].failed
    assert by_id["web-2"].exempt_reason == "off-limits"
    assert [a.asset_id for a in report.exempt_assets] == ["web-2"]
    assert report.failed_assets == []


# --- MCP surface --------------------------------------------------------

def test_mcp_list_and_report_show_exempt(tmp_path):
    eng = build_engine()
    eng.registry.register(_ssh_asset("mcp-1"))
    eng.registry.set_scan_exempt("mcp-1", True, "off-limits")

    assets = handle_call(eng, "list_assets", {})["assets"]
    assert any(a["asset_id"] == "mcp-1" and a["scan_exempt"] for a in assets)

    out = handle_call(eng, "report", {"asset_ids": ["mcp-1"], "out_dir": str(tmp_path)})
    assert out["summary"]["exempt_assets"] == ["mcp-1"]
    assert out["summary"]["failed_assets"] == []


# --- operator CLI -------------------------------------------------------

def test_cli_scan_exempt(tmp_path):
    from ai_defense.__main__ import main
    from ai_defense.db.repositories import AssetRepository

    db = f"sqlite+pysqlite:///{(tmp_path / 'e.db').as_posix()}"
    AssetRepository(init_db(db)).save(_ssh_asset("cli-1"))

    assert main(["scan-exempt", "--db", db, "--asset-id", "cli-1", "--reason", "off-limits"]) == 0
    assert AssetRepository(init_db(db)).get("cli-1").attributes.get("scan_exempt") is True

    assert main(["scan-exempt", "--db", db, "--asset-id", "cli-1", "--clear"]) == 0
    assert AssetRepository(init_db(db)).get("cli-1").attributes.get("scan_exempt") is None
