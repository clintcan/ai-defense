"""Asset onboarding: operator helper (option 1) and LLM-proposed tool (option 2)."""

from datetime import UTC, datetime, timedelta

from ai_defense.approval.gate import ApprovalGate
from ai_defense.audit.log import AuditLog
from ai_defense.db import AssetRepository, init_db
from ai_defense.onboarding import (
    ASSET_REGISTER_TOOL,
    build_ssh_asset,
    make_asset_register_tool,
    register_ssh_host,
)
from ai_defense.registry.assets import Asset, AssetRegistry, Authorization
from ai_defense.toolset.dispatch import Dispatcher
from ai_defense.toolset.intents import ActionClass, Intent
from ai_defense.toolset.policy import PolicyEngine
from ai_defense.toolset.registry import ToolRegistry
from ai_defense.vault.vault import SecretsBackend, Vault

NOW = datetime(2026, 11, 3, tzinfo=UTC)

POLICY = {
    "autonomous_action_classes": ["discovery", "scan", "protective"],
    "approvals": {"onboard": {"required": 1}},
}


# --- option 1: operator helper / persistence ----------------------------

def test_operator_register_persists_connection_info():
    repo = AssetRepository(init_db())
    register_ssh_host(
        repo, asset_id="vps-blog-01", host="203.0.113.10", key_ref="ssh-key/vps-blog-01",
        owner="me", environment="prod", granted_by="me", attestation_sig="sig-123",
        user="ubuntu", port=2222, now=NOW,
    )
    got = repo.get("vps-blog-01")
    assert got.kind == "ssh-host"
    assert got.connection.host == "203.0.113.10"
    assert got.connection.user == "ubuntu" and got.connection.port == 2222
    assert got.connection.key_ref == "ssh-key/vps-blog-01"
    assert got.authorization.valid(NOW)


def test_build_ssh_asset_defaults():
    a = build_ssh_asset(asset_id="h", host="10.0.0.1", key_ref="k", owner="o",
                        environment="prod", granted_by="x", attestation_sig="s", now=NOW)
    assert a.connection.port == 22 and a.connection.user == "root"
    assert a.authorization.expires_at == NOW + timedelta(days=90)


# --- option 2: LLM-proposed, approval-gated tool ------------------------

class _Vault(SecretsBackend):
    def __init__(self, known):
        self._known = known
        self.log = []

    def resolve(self, ref):
        self.log.append(ref)
        if ref not in self._known:
            raise KeyError(ref)
        return self._known[ref]

    def audit_access(self, ref, *, actor, reason):
        pass


def _control_plane_registry():
    reg = AssetRegistry()
    reg.register(Asset("control-plane", "control-plane", "secops", "mgmt",
                       Authorization("root-sig", "ciso", NOW - timedelta(days=1),
                                     NOW + timedelta(days=365))))
    return reg


def _onboard_dispatcher(known_keys):
    reg = _control_plane_registry()
    tools = ToolRegistry()
    tools.register(make_asset_register_tool(reg.register))     # writes into the registry
    approvals = ApprovalGate()
    vault = Vault(_Vault(known_keys))
    disp = Dispatcher(registry=tools, policy=PolicyEngine(POLICY), assets=reg,
                      approvals=approvals, vault=vault, audit=AuditLog(clock=lambda: NOW),
                      clock=lambda: NOW)
    return disp, approvals, reg


def _onboard_intent():
    return Intent(
        tool=ASSET_REGISTER_TOOL,
        params={"asset_id": "vps-blog-01", "host": "203.0.113.10",
                "key_ref": "ssh-key/vps-blog-01", "owner": "me",
                "environment": "prod", "granted_by": "me"},
        targets=["control-plane"],          # authority to onboard, not the new asset
        action_class=ActionClass.ONBOARD, reason="add VPS for patching",
    )


def test_onboard_requires_approval_then_registers():
    disp, approvals, reg = _onboard_dispatcher({"ssh-key/vps-blog-01": "KEYDATA"})
    intent = _onboard_intent()

    pending = disp.dispatch(intent)
    assert not pending.ok and pending.data["approval_state"] == "pending"
    import pytest
    with pytest.raises(PermissionError):          # not registered yet
        reg.require_authorized("vps-blog-01", NOW)

    approvals.decide(pending.data["change_set_id"], "secops-lead", approve=True, now=NOW)
    res = disp.dispatch(intent)
    assert res.ok
    # registered + authorized (granted_at is stamped at real wall-clock time)
    asset = reg.require_authorized("vps-blog-01", datetime.now(UTC))
    assert asset.connection.host == "203.0.113.10"
    assert asset.connection.key_ref == "ssh-key/vps-blog-01"


def test_onboard_is_rejected_if_key_not_in_vault():
    disp, approvals, reg = _onboard_dispatcher(known_keys={})   # vault has no key
    intent = _onboard_intent()
    approvals_id = disp.dispatch(intent).data["change_set_id"]
    approvals.decide(approvals_id, "lead", approve=True, now=NOW)
    res = disp.dispatch(intent)
    # resolve_secret raises KeyError -> dispatcher fail-safe deny; nothing registered
    assert not res.ok
    import pytest
    with pytest.raises(PermissionError):
        reg.require_authorized("vps-blog-01", NOW)


def test_onboard_private_key_is_never_a_parameter():
    # The tool schema accepts only key_ref, not the key itself.
    spec = make_asset_register_tool(lambda a: None)
    props = spec.schema["properties"]
    assert "key_ref" in props
    assert not any("key" == k or k.endswith("private_key") for k in props if k != "key_ref")


def test_onboard_cannot_run_without_authorized_control_plane():
    # Targeting an unregistered control plane is denied before any write.
    disp, approvals, reg = _onboard_dispatcher({"ssh-key/vps-blog-01": "KEYDATA"})
    intent = Intent(
        tool=ASSET_REGISTER_TOOL,
        params=_onboard_intent().params,
        targets=["ghost-control-plane"], action_class=ActionClass.ONBOARD, reason="x",
    )
    res = disp.dispatch(intent)
    assert not res.ok and "authorization" in res.data["reason"]
