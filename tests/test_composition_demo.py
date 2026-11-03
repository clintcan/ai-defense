"""The composition root wires a runnable engine, and the demo runs end to end."""

from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_demo_engine
from ai_defense.demo import scripted_demo
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.vuln.planner import RemediationKind


def test_engine_wires_all_tools():
    eng = build_demo_engine()
    names = eng.dispatcher.registry.names()
    for expected in [
        "asset.register", "patch.apply_security_update",
        "aws.ec2.list_instances", "aws.lightsail.list_instances",
        "aws.ssm.describe_patch_state", "aws.snapshot_before_change",
        "aws.delete_snapshots", "aws.ssm.apply_patch_baseline",
    ]:
        assert expected in names
    # control-plane authority is seeded so onboarding has a valid target
    assert eng.registry.get("control-plane") is not None


def test_onboarding_is_approval_gated_then_registers():
    eng = build_demo_engine()
    params = dict(asset_id="vps-x", host="198.51.100.9", key_ref="ssh-key/vps-demo-01",
                  owner="ops", environment="prod", granted_by="operator")
    pending = eng.onboard_ssh(**params)
    assert not pending.ok and pending.data["approval_state"] == "pending"
    assert eng.registry.get("vps-x") is None            # nothing registered yet

    eng.approve(pending.data["change_set_id"])
    done = eng.onboard_ssh(**params)
    assert done.ok
    asset = eng.registry.get("vps-x")
    assert asset.connection.host == "198.51.100.9"


def test_scan_plan_remediate_flow():
    eng = build_demo_engine()
    # onboard the host directly (authorization + connection) so remediation can target it
    now = datetime.now(UTC)
    eng.registry.register(Asset(
        "vps-demo-01", "ssh-host", "ops", "prod",
        Authorization("sig", "operator", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="198.51.100.20", key_ref="ssh-key/vps-demo-01"),
    ))
    inventory = eng.scan(["vps-demo-01"])
    assert inventory[0].installed_packages["openssl"] == "3.0.5"

    plan = eng.plan(inventory)
    kinds = {it.cve_id: it.kind for it in plan}
    assert kinds["CVE-2026-1001"] == RemediationKind.PATCH          # has a fix
    assert kinds["CVE-2026-1002"] == RemediationKind.MITIGATION     # no patch
    # KEV patch is prioritized first
    assert plan[0].cve_id == "CVE-2026-1001"

    patch_item = plan[0]
    pending = eng.remediate(patch_item, snapshot=False)
    assert pending.status == "patch_pending"
    eng.approve(pending.patch.data["change_set_id"])
    applied = eng.remediate(patch_item, snapshot=False)
    assert applied.status == "patched"
    assert eng.audit_ok()


def test_scripted_demo_runs_and_audit_verifies():
    steps = scripted_demo()
    titles = " | ".join(s.title for s in steps)
    assert "Onboard" in titles and "Remediate" in titles
    # the final step reports audit verification
    assert "verify=True" in steps[-1].title
