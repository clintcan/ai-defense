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


def test_build_ssh_engine_uses_real_backends_wiring(tmp_path, monkeypatch):
    # build_ssh_engine should wire a paramiko transport + file vault + SSH
    # inspector. We verify the wiring (file vault + inspector over a transport)
    # by injecting a fake paramiko and a key file, then scanning an onboarded
    # host end to end.
    import sys
    import types

    from ai_defense.composition import build_ssh_engine
    from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo

    # minimal fake paramiko whose exec_command returns a dpkg inventory
    class _Chan:
        def recv_exit_status(self): return 0
    class _S:
        def __init__(self, d, c=None):
            self._d = d
            self.channel = c
        def read(self): return self._d
    class _Client:
        def load_host_keys(self, p): pass
        def load_system_host_keys(self): pass
        def set_missing_host_key_policy(self, p): pass
        def connect(self, **k): pass
        def exec_command(self, command, timeout=None, get_pty=False):
            return (None, _S(b"openssl 3.0.5\n", _Chan()), _S(b""))
        def close(self): pass
    pm = types.ModuleType("paramiko")
    pm.SSHException = type("SSHException",(Exception,),{})
    pm.Ed25519Key = type("K",(),{"from_private_key": classmethod(lambda c,*a,**k: object())})
    pm.RSAKey = pm.Ed25519Key
    pm.SSHClient = _Client
    pm.AutoAddPolicy = type("A",(),{})
    pm.RejectPolicy = type("R",(),{})
    monkeypatch.setitem(sys.modules, "paramiko", pm)

    # key file in the vault dir
    (tmp_path / "ssh-key").mkdir()
    (tmp_path / "ssh-key" / "vps-real-01").write_text("KEYDATA")

    sf = init_db()
    eng = build_ssh_engine(key_dir=str(tmp_path), session_factory=sf,
                           allow_unknown_hosts=True)
    now = datetime.now(UTC)
    eng.registry.register(Asset(
        "vps-real-01", "ssh-host", "ops", "prod",
        Authorization("sig","op",now-timedelta(minutes=1),now+timedelta(days=90)),
        connection=ConnectionInfo(host="203.0.113.70", key_ref="ssh-key/vps-real-01")))

    inv = eng.scan(["vps-real-01"])
    assert inv[0].installed_packages == {"openssl": "3.0.5"}   # came over (fake) SSH
