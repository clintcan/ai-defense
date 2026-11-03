"""End-to-end: mitigate a CVE on a canary host through the full pipeline.

Intent -> dispatcher -> capability/authorization/policy -> approval gate ->
SSH executor (dry-run first) -> audited result with a recorded rollback action.
Uses a fake SSH transport and in-memory fakes; no real hosts or secrets.
"""

from datetime import UTC, datetime, timedelta

from ai_defense.approval.gate import ApprovalGate
from ai_defense.audit.log import AuditLog
from ai_defense.registry.assets import Asset, AssetRegistry, Authorization
from ai_defense.ssh.executor import CommandOutput, SSHExecutor
from ai_defense.ssh.tools import SECURITY_UPDATE_TOOL, make_security_update_tool
from ai_defense.toolset.dispatch import Dispatcher
from ai_defense.toolset.intents import ActionClass, Intent
from ai_defense.toolset.policy import PolicyEngine
from ai_defense.toolset.registry import ToolRegistry
from ai_defense.vault.vault import SecretsBackend, Vault

NOW = datetime(2026, 11, 3, tzinfo=UTC)
SECRET_KEY = "PRIVATE-SSH-KEY-MATERIAL"

POLICY = {
    "autonomous_action_classes": ["discovery", "scan", "protective"],
    "blast_radius_caps": {"patch_canary": 3},
    "approvals": {"patch_canary": {"required": 1}},
}


class FakeBackend(SecretsBackend):
    def __init__(self):
        self.access_log = []

    def resolve(self, ref):
        return SECRET_KEY

    def audit_access(self, ref, *, actor, reason):
        self.access_log.append((ref, actor, reason))


class FakeTransport:
    def __init__(self):
        self.calls = []

    def run(self, host, argv, *, key, timeout):
        self.calls.append((host, tuple(argv), key))
        # dry-run and apply both succeed
        return CommandOutput(0, f"upgraded on {host}", "")


def _build():
    transport = FakeTransport()
    registry = ToolRegistry()
    registry.register(make_security_update_tool(SSHExecutor(transport)))
    assets = AssetRegistry()
    assets.register(Asset("canary-01", "ssh-host", "team", "web-prod",
                          Authorization("sig", "lead", NOW - timedelta(days=1),
                                        NOW + timedelta(days=30))))
    approvals = ApprovalGate()
    audit = AuditLog(clock=lambda: NOW)
    disp = Dispatcher(
        registry=registry, policy=PolicyEngine(POLICY), assets=assets,
        approvals=approvals, vault=Vault(FakeBackend()), audit=audit, clock=lambda: NOW,
    )
    return disp, approvals, audit, transport


def _intent():
    return Intent(
        tool=SECURITY_UPDATE_TOOL,
        params={"host": "canary-01", "package": "openssl", "key_ref": "ssh-key/canary",
                "snapshot_id": "snap-123"},
        targets=["canary-01"],
        action_class=ActionClass.PATCH_CANARY,
        reason="remediate CVE-2026-1234 (OpenSSL)",
        source_ref="CVE-2026-1234",
    )


def test_pending_until_approved_then_applies():
    disp, approvals, audit, transport = _build()
    intent = _intent()

    # 1. First submission: blocked pending approval, nothing executed.
    pending = disp.dispatch(intent)
    assert not pending.ok and "awaiting approval" in pending.summary
    assert transport.calls == []

    # 2. Human approves the change-set.
    cs_id = pending.data["change_set_id"]
    approvals.decide(cs_id, "secops-lead", approve=True, now=NOW)

    # 3. Re-submission now executes: dry-run first, then apply.
    res = disp.dispatch(intent)
    assert res.ok
    assert res.summary == "openssl upgraded on canary-01"
    assert len(transport.calls) == 2
    assert "--simulate" in transport.calls[0][1]
    assert "--simulate" not in transport.calls[1][1]

    # 4. Result carries a recorded rollback action citing the snapshot.
    rb = res.data["rollback"]
    assert rb["kind"] == "package"
    assert rb["payload"]["snapshot_id"] == "snap-123"

    # 5. resolved_command is auditable and secret-free.
    assert "apt-get" in res.resolved_command
    assert SECRET_KEY not in res.resolved_command


def test_secret_never_leaks_to_result_or_audit():
    disp, approvals, audit, transport = _build()
    intent = _intent()
    cs_id = disp.dispatch(intent).data["change_set_id"]
    approvals.decide(cs_id, "lead", approve=True, now=NOW)
    res = disp.dispatch(intent)
    assert res.ok

    assert SECRET_KEY not in str(res.data)
    assert SECRET_KEY not in (res.resolved_command or "")
    blob = "".join(str(r.payload) for r in audit.records())
    assert SECRET_KEY not in blob
    assert audit.verify()


def test_source_ref_recorded_in_audit():
    disp, approvals, audit, transport = _build()
    intent = _intent()
    cs_id = disp.dispatch(intent).data["change_set_id"]
    approvals.decide(cs_id, "lead", approve=True, now=NOW)
    disp.dispatch(intent)
    blob = "".join(str(r.payload) for r in audit.records())
    assert "CVE-2026-1234" in blob
