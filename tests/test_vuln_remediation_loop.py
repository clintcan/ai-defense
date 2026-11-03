"""Full loop: observed inventory + advisory -> plan -> dispatch remediation.

Proves the planner's patch Intent flows through the real dispatcher, approval
gate, and SSH executor (dry-run first) against a fake host.
"""

from datetime import UTC, datetime, timedelta

from ai_defense.approval.gate import ApprovalGate
from ai_defense.audit.log import AuditLog
from ai_defense.registry.assets import (
    Asset,
    AssetRegistry,
    Authorization,
    ConnectionInfo,
)
from ai_defense.scanner.scanner import AuthenticatedScanner
from ai_defense.ssh.executor import CommandOutput, SSHExecutor
from ai_defense.ssh.tools import make_security_update_tool, registry_connection_resolver
from ai_defense.toolset.dispatch import Dispatcher
from ai_defense.toolset.intents import ActionClass, Intent
from ai_defense.toolset.policy import PolicyEngine
from ai_defense.toolset.registry import ToolRegistry
from ai_defense.vault.vault import SecretsBackend, Vault
from ai_defense.vuln.feeds import Advisory, AffectedPackage
from ai_defense.vuln.planner import RemediationKind, RemediationPlanner

NOW = datetime(2026, 11, 3, tzinfo=UTC)
SECRET = "SSH-KEY-FOR-CANARY"

POLICY = {
    "autonomous_action_classes": ["discovery", "scan", "protective"],
    "blast_radius_caps": {"patch_canary": 3},
    "approvals": {"patch_canary": {"required": 1}},
}


class _Backend(SecretsBackend):
    def resolve(self, ref):
        return SECRET

    def audit_access(self, ref, *, actor, reason):
        pass


class _Inspector:
    """Returns a vulnerable openssl on the canary."""

    def collect(self, asset_id):
        return {"installed_packages": {"openssl": "3.0.5"}}


class _Transport:
    def __init__(self):
        self.calls = []

    def run(self, host, argv, *, key, timeout, user="root", port=22):
        self.calls.append((host, user, port, tuple(argv)))
        return CommandOutput(0, "ok", "")


def test_scan_to_plan_to_remediation():
    # 1. Observe the fleet (read-only scanner).
    inventory = AuthenticatedScanner(_Inspector()).scan_hosts(["canary-01"])

    # 2. Correlate against an advisory with a fix, and plan.
    adv = Advisory("CVE-2026-1234", "osv",
                   [AffectedPackage("openssl", fixed_version="3.0.8", introduced="3.0.0")],
                   cvss=7.5, kev=True)
    planner = RemediationPlanner()
    items = planner.plan([adv], inventory)
    assert len(items) == 1 and items[0].kind == RemediationKind.PATCH
    patch_intent = items[0].intent
    assert patch_intent.params == {"asset_id": "canary-01", "package": "openssl"}

    # 3. Build the real enforcement stack; the patch tool resolves the host's
    #    connection (host/user/port/key_ref) from the trusted registry.
    transport = _Transport()
    assets = AssetRegistry()
    assets.register(Asset("canary-01", "ssh-host", "team", "web-prod",
                          Authorization("sig", "lead", NOW - timedelta(days=1),
                                        NOW + timedelta(days=30)),
                          connection=ConnectionInfo(host="203.0.113.10",
                                                    key_ref="ssh-key/canary-01",
                                                    user="ubuntu", port=2222)))
    reg = ToolRegistry()
    reg.register(make_security_update_tool(
        SSHExecutor(transport), registry_connection_resolver(assets, clock=lambda: NOW)))
    approvals = ApprovalGate()
    audit = AuditLog(clock=lambda: NOW)
    disp = Dispatcher(registry=reg, policy=PolicyEngine(POLICY), assets=assets,
                      approvals=approvals, vault=Vault(_Backend()), audit=audit,
                      clock=lambda: NOW)

    # 4. Dispatch the planned intent: pending until approved, then applied.
    pending = disp.dispatch(patch_intent)
    assert not pending.ok and "awaiting approval" in pending.summary
    assert transport.calls == []                         # nothing ran yet

    approvals.decide(pending.data["change_set_id"], "secops-lead", approve=True, now=NOW)
    res = disp.dispatch(patch_intent)
    assert res.ok
    assert res.summary == "openssl upgraded on canary-01"

    # 5. Connection came from the registry (not planner text): right host/user/port.
    assert transport.calls[0][0] == "203.0.113.10"
    assert transport.calls[0][1] == "ubuntu" and transport.calls[0][2] == 2222
    # Dry-run ran before the real apply, and the CVE is in the audit trail.
    assert "--simulate" in transport.calls[0][3]
    assert "--simulate" not in transport.calls[1][3]
    assert res.data["rollback"]["kind"] == "package"
    blob = "".join(str(r.payload) for r in audit.records())
    assert "CVE-2026-1234" in blob
    assert SECRET not in blob and SECRET not in str(res.data)


def test_patch_refused_for_asset_without_registered_connection():
    # Security: the patch tool resolves host/key_ref from the registry, so an
    # asset with no connection info cannot be reached (fails safe), and an
    # unregistered asset is denied outright.
    transport = _Transport()
    assets = AssetRegistry()
    # registered + authorized but NO connection info
    assets.register(Asset("no-conn", "ssh-host", "t", "web-prod",
                          Authorization("s", "l", NOW - timedelta(days=1),
                                        NOW + timedelta(days=30))))
    reg = ToolRegistry()
    reg.register(make_security_update_tool(
        SSHExecutor(transport), registry_connection_resolver(assets, clock=lambda: NOW)))
    approvals = ApprovalGate()
    disp = Dispatcher(registry=reg, policy=PolicyEngine(POLICY), assets=assets,
                      approvals=approvals, vault=Vault(_Backend()),
                      audit=AuditLog(clock=lambda: NOW), clock=lambda: NOW)
    intent = Intent(tool="patch.apply_security_update",
                    params={"asset_id": "no-conn", "package": "openssl"},
                    targets=["no-conn"], action_class=ActionClass.PATCH_CANARY,
                    reason="r")
    cs_id = disp.dispatch(intent).data["change_set_id"]
    approvals.decide(cs_id, "lead", approve=True, now=NOW)
    res = disp.dispatch(intent)
    assert not res.ok                                  # resolver raised -> fail-safe deny
    assert transport.calls == []                       # never connected anywhere
