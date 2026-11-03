"""The `report` CLI subcommand and the fleet-sweep asset selection."""

import os
from datetime import UTC, datetime, timedelta

from ai_defense.__main__ import _fleet_asset_ids, main
from ai_defense.composition import build_demo_engine
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo


def _ssh_asset(asset_id="vps-01"):
    now = datetime.now(UTC)
    return Asset(
        asset_id, "ssh-host", "ops", "prod",
        Authorization("sig", "operator", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="198.51.100.20", key_ref="ssh-key/vps-01"),
    )


# --- fleet selection -----------------------------------------------------

def test_fleet_asset_ids_selects_only_ssh_hosts():
    eng = build_demo_engine()                 # registry has a control-plane asset only
    assert _fleet_asset_ids(eng) == []        # control-plane is not ssh-scannable
    eng.registry.register(_ssh_asset("vps-01"))
    eng.registry.register(_ssh_asset("vps-02"))
    assert sorted(_fleet_asset_ids(eng)) == ["vps-01", "vps-02"]


# --- report command ------------------------------------------------------

def test_report_command_writes_files(tmp_path, capsys):
    rc = main(["report", "any-host", "--out-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "finding(s)" in out
    for name in ("executive-summary.md", "technical-report.md",
                 "findings.generic.json", "findings.defectdojo.json"):
        assert (tmp_path / name).exists()
    # the printed summary lists the written paths
    assert "executive_summary" in out


def test_fleet_report_aggregates_multiple_hosts(tmp_path):
    eng = build_demo_engine()
    eng.registry.register(_ssh_asset("vps-01"))
    eng.registry.register(_ssh_asset("vps-02"))
    report, _ = eng.report(_fleet_asset_ids(eng), out_dir=str(tmp_path))
    assert sorted(a.asset_id for a in report.assets) == ["vps-01", "vps-02"]
    # findings aggregate across the fleet (demo inspector reports on each host)
    assert len(report.all_findings) == 2 * len(report.assets[0].findings)


def test_report_command_requires_targets(capsys):
    rc = main(["report"])                     # no assets, no --all
    assert rc == 1
    assert "no assets to report on" in capsys.readouterr().out


def test_report_all_with_no_fleet_is_graceful(capsys):
    rc = main(["report", "--all"])            # demo registry has no ssh-host assets
    assert rc == 1
    assert "no assets to report on" in capsys.readouterr().out


def test_report_default_out_dir_is_timestamped(tmp_path, monkeypatch, capsys):
    # With no --out-dir it writes under ./reports/<timestamp>; run in a temp cwd
    # so the repo isn't touched.
    monkeypatch.chdir(tmp_path)
    rc = main(["report", "any-host"])
    assert rc == 0
    reports = tmp_path / "reports"
    assert reports.is_dir()
    stamp_dirs = list(reports.iterdir())
    assert len(stamp_dirs) == 1
    assert (stamp_dirs[0] / "findings.defectdojo.json").exists()
    assert os.path.basename(str(stamp_dirs[0])).endswith("Z")   # UTC timestamp dir
