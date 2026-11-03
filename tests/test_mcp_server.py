"""MCP tool manifest + call handler, driven like a chat session would."""

from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_demo_engine
from ai_defense.mcp_server import TOOLS, handle_call, tool_names
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo


def _engine_with_host():
    eng = build_demo_engine()
    now = datetime.now(UTC)
    eng.registry.register(Asset(
        "vps-demo-01", "ssh-host", "ops", "prod",
        Authorization("sig", "operator", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="198.51.100.20", key_ref="ssh-key/vps-demo-01"),
    ))
    return eng


def test_manifest_shape():
    assert set(tool_names()) == {
        "list_assets", "scan", "plan", "remediate", "approve_change", "audit_tail"}
    for t in TOOLS:
        assert t["inputSchema"]["type"] == "object"       # valid JSON-schema stub


def test_list_and_scan():
    eng = _engine_with_host()
    assets = handle_call(eng, "list_assets", {})["assets"]
    assert any(a["asset_id"] == "vps-demo-01" for a in assets)

    findings = handle_call(eng, "scan", {"asset_ids": ["vps-demo-01"]})["findings"]
    assert findings[0]["installed_packages"]["openssl"] == "3.0.5"


def test_plan_is_prioritized():
    eng = _engine_with_host()
    plan = handle_call(eng, "plan", {"asset_ids": ["vps-demo-01"]})["plan"]
    assert plan[0]["cve_id"] == "CVE-2026-1001"           # KEV patch first
    assert plan[0]["kind"] == "patch"


def test_remediate_flow_pending_then_approved():
    eng = _engine_with_host()
    pend = handle_call(eng, "remediate", {"asset_id": "vps-demo-01", "package": "openssl"})
    assert pend["status"] == "patch_pending"
    assert "change_set_id" in pend

    appr = handle_call(eng, "approve_change",
                       {"change_set_id": pend["change_set_id"], "approver": "secops-lead"})
    assert appr["state"] == "approved"

    done = handle_call(eng, "remediate", {"asset_id": "vps-demo-01", "package": "openssl"})
    assert done["status"] == "patched"


def test_remediate_unregistered_is_blocked_not_applied():
    eng = build_demo_engine()      # vps-demo-01 NOT registered here
    res = handle_call(eng, "remediate", {"asset_id": "vps-demo-01", "package": "openssl"})
    # the patch item exists in the plan but dispatch denies at authorization
    assert res["status"] == "patch_blocked"


def test_remediate_no_patch_available():
    eng = _engine_with_host()
    res = handle_call(eng, "remediate", {"asset_id": "vps-demo-01", "package": "bash"})
    assert res["status"] == "no_patch_available"          # bash advisory has no fix


def test_audit_tail_reports_verification():
    eng = _engine_with_host()
    handle_call(eng, "scan", {"asset_ids": ["vps-demo-01"]})
    out = handle_call(eng, "audit_tail", {"n": 5})
    assert out["verified"] is True
    assert isinstance(out["records"], list)


def test_unknown_tool_and_missing_arg_return_errors():
    eng = _engine_with_host()
    assert "error" in handle_call(eng, "nope", {})
    assert "error" in handle_call(eng, "scan", {})        # missing asset_ids
