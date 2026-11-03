"""Durable engine: registry + approvals + audit survive restarts and are shared
across processes when backed by a DB."""

from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_engine
from ai_defense.db import AssetRepository, init_db
from ai_defense.onboarding import register_ssh_host
from ai_defense.registry.assets import Asset, Authorization


def _onboard_params(asset_id="vps-dur-01"):
    return dict(asset_id=asset_id, host="198.51.100.30", key_ref="ssh-key/vps-demo-01",
                owner="ops", environment="prod", granted_by="operator")


def test_control_plane_seeded_once_and_durable():
    sf = init_db()
    build_engine(session_factory=sf)
    build_engine(session_factory=sf)                 # second build must not duplicate
    assert len(AssetRepository(sf).all()) == 1       # just the control-plane
    assert AssetRepository(sf).get("control-plane") is not None


def test_onboarded_asset_survives_a_fresh_engine():
    sf = init_db()
    eng = build_engine(session_factory=sf)
    # onboard through the approval-gated tool
    pending = eng.onboard_ssh(**_onboard_params())
    eng.approve(pending.data["change_set_id"])
    done = eng.onboard_ssh(**_onboard_params())
    assert done.ok

    # a brand-new engine on the SAME db still sees the asset, authorized
    eng2 = build_engine(session_factory=sf)
    asset = eng2.registry.require_authorized("vps-dur-01", datetime.now(UTC))
    assert asset.connection.host == "198.51.100.30"
    assert any(a.asset_id == "vps-dur-01" for a in eng2.list_assets())


def test_in_memory_engine_does_not_persist():
    sf = init_db()
    eng = build_engine()                             # no db -> in-memory
    eng.registry.register(Asset(
        "ephemeral", "ssh-host", "o", "prod",
        Authorization("s", "l", datetime.now(UTC) - timedelta(minutes=1),
                      datetime.now(UTC) + timedelta(days=1))))
    assert AssetRepository(sf).get("ephemeral") is None   # nothing written to db


def test_cli_registered_asset_is_visible_to_running_engine():
    # Cross-process: operator registers via the CLI helper; the engine's
    # DB-backed registry sees it live (no restart needed).
    sf = init_db()
    eng = build_engine(session_factory=sf)
    assert eng.registry.get("vps-cli-01") is None

    register_ssh_host(
        AssetRepository(sf), asset_id="vps-cli-01", host="203.0.113.50",
        key_ref="ssh-key/vps-demo-01", owner="ops", environment="prod",
        granted_by="operator", attestation_sig="sig-cli")

    asset = eng.registry.require_authorized("vps-cli-01", datetime.now(UTC))
    assert asset.connection.host == "203.0.113.50"


def test_full_durable_flow_remediates_cli_onboarded_host():
    sf = init_db()
    eng = build_engine(session_factory=sf)
    # onboard a host out-of-band with a connection the demo vault can resolve
    register_ssh_host(
        AssetRepository(sf), asset_id="vps-demo-01", host="198.51.100.20",
        key_ref="ssh-key/vps-demo-01", owner="ops", environment="prod",
        granted_by="operator", attestation_sig="sig")

    item = next(it for it in eng.plan(eng.scan(["vps-demo-01"])) if it.intent)
    pending = eng.remediate(item, snapshot=False)
    assert pending.status == "patch_pending"
    eng.approve(pending.patch.data["change_set_id"])
    assert eng.remediate(item, snapshot=False).status == "patched"
    assert eng.audit_ok()
