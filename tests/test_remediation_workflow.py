"""Remediation workflow: optional snapshot -> patch -> optional snapshot delete."""

from datetime import UTC, datetime, timedelta

from ai_defense.approval.gate import ApprovalGate
from ai_defense.audit.log import AuditLog
from ai_defense.cloud.tools import make_snapshot_delete_tool, make_snapshot_tool
from ai_defense.registry.assets import Asset, AssetRegistry, Authorization
from ai_defense.scanner.scanner import HostFindings
from ai_defense.ssh.executor import CommandOutput, SSHExecutor
from ai_defense.ssh.tools import make_security_update_tool
from ai_defense.toolset.dispatch import Dispatcher
from ai_defense.toolset.policy import PolicyEngine
from ai_defense.toolset.registry import ToolRegistry
from ai_defense.vault.vault import SecretsBackend, Vault
from ai_defense.vuln.feeds import Advisory, AffectedPackage
from ai_defense.vuln.planner import RemediationKind, RemediationPlanner
from ai_defense.vuln.workflow import (
    NOT_A_PATCH,
    PATCH_PENDING,
    PATCHED,
    SNAPSHOT_FAILED,
    RemediationWorkflow,
)

NOW = datetime(2026, 11, 3, tzinfo=UTC)

POLICY = {
    "autonomous_action_classes": ["discovery", "scan", "protective"],
    "blast_radius_caps": {"patch_canary": 3},
    "approvals": {"patch_canary": {"required": 1}, "cleanup": {"required": 1}},
}


class _Backend(SecretsBackend):
    def resolve(self, ref):
        return {"profile": "secops"} if ref.startswith("aws/") else "SSH-KEY"

    def audit_access(self, ref, *, actor, reason):
        pass


class _SSHTransport:
    def __init__(self):
        self.calls = []

    def run(self, host, argv, *, key, timeout):
        self.calls.append(tuple(argv))
        return CommandOutput(0, "ok", "")


class _FakeCloud:
    def __init__(self, volumes=("vol-a",)):
        self.calls = []
        self._volumes = list(volumes)

    def describe_instance_volumes(self, instance_id):
        self.calls.append(("describe_volumes", instance_id))
        return [{"VolumeId": v} for v in self._volumes]

    def create_ebs_snapshot(self, volume_id, description, tags):
        self.calls.append(("create_snapshot", volume_id))
        return {"SnapshotId": f"snap-{volume_id}"}

    def delete_ebs_snapshot(self, snapshot_id):
        self.calls.append(("delete_snapshot", snapshot_id))
        return {}

    # unused by these tests but required by the client protocol surface
    def describe_instances(self, **k): return []
    def describe_instance_patch_states(self, ids): return []
    def get_lightsail_instances(self): return []
    def create_lightsail_snapshot(self, n, s): return {}
    def delete_lightsail_snapshot(self, n): return {}


def _patch_item():
    adv = Advisory("CVE-2026-1", "osv",
                   [AffectedPackage("openssl", fixed_version="3.0.8")], cvss=7.5)
    planner = RemediationPlanner(key_ref_for=lambda a: f"ssh-key/{a}")
    items = planner.plan([adv], [HostFindings("canary-01", {"openssl": "3.0.5"})])
    assert items[0].kind == RemediationKind.PATCH
    return items[0]


def _build(cloud):
    transport = _SSHTransport()
    reg = ToolRegistry()
    reg.register(make_security_update_tool(SSHExecutor(transport)))
    reg.register(make_snapshot_tool(lambda creds: cloud))
    reg.register(make_snapshot_delete_tool(lambda creds: cloud))
    assets = AssetRegistry()
    assets.register(Asset("canary-01", "ec2-instance", "team", "web-prod",
                          Authorization("s", "l", NOW - timedelta(days=1),
                                        NOW + timedelta(days=30))))
    approvals = ApprovalGate()
    audit = AuditLog(clock=lambda: NOW)
    disp = Dispatcher(registry=reg, policy=PolicyEngine(POLICY), assets=assets,
                      approvals=approvals, vault=Vault(_Backend()), audit=audit,
                      clock=lambda: NOW)
    wf = RemediationWorkflow(disp, credential_ref_for=lambda a: "aws/snapshot-role")
    return wf, disp, approvals, transport, cloud


# --- snapshot-then-patch sequencing -------------------------------------

def test_snapshot_taken_before_patch_then_applied_after_approval():
    wf, disp, approvals, transport, cloud = _build(_FakeCloud())
    item = _patch_item()

    # First run: snapshot taken (autonomous), patch pending — nothing applied yet.
    r1 = wf.run(item)
    assert r1.status == PATCH_PENDING
    assert r1.snapshot_ids == ["snap-vol-a"]
    assert ("create_snapshot", "vol-a") in cloud.calls
    assert transport.calls == []                       # patch not executed yet

    # Approve, then re-run passing the existing snapshot id -> no second snapshot.
    cs_id = r1.patch.data["change_set_id"]
    approvals.decide(cs_id, "lead", approve=True, now=NOW)
    snapshot_calls_before = cloud.calls.count(("create_snapshot", "vol-a"))
    r2 = wf.run(item, existing_snapshot_ids=r1.snapshot_ids)
    assert r2.status == PATCHED
    assert cloud.calls.count(("create_snapshot", "vol-a")) == snapshot_calls_before
    assert "--simulate" in transport.calls[0] and "--simulate" not in transport.calls[1]


def test_snapshot_can_be_disabled():
    wf, disp, approvals, transport, cloud = _build(_FakeCloud())
    r = wf.run(_patch_item(), snapshot=False)
    assert r.status == PATCH_PENDING
    assert r.snapshot_ids == []
    assert not any(c[0] == "create_snapshot" for c in cloud.calls)


def test_snapshot_failure_aborts_patch():
    # No volumes -> snapshot adapter raises -> dispatcher denies -> patch skipped.
    wf, disp, approvals, transport, cloud = _build(_FakeCloud(volumes=()))
    r = wf.run(_patch_item())
    assert r.status == SNAPSHOT_FAILED
    assert not r.snapshot.ok
    assert transport.calls == []                       # never patched without a backup


def test_non_patch_item_does_nothing():
    wf, *_ = _build(_FakeCloud())
    adv = Advisory("CVE-X", "osv", [AffectedPackage("foo", fixed_version=None)],
                   mitigation="disable foo")
    planner = RemediationPlanner(key_ref_for=lambda a: f"ssh-key/{a}")
    mitigation = planner.plan([adv], [HostFindings("canary-01", {"foo": "1.0"})])[0]
    assert mitigation.kind == RemediationKind.MITIGATION
    assert wf.run(mitigation).status == NOT_A_PATCH


# --- deliberate snapshot cleanup ----------------------------------------

def test_delete_snapshot_is_approval_gated_then_deletes():
    wf, disp, approvals, transport, cloud = _build(_FakeCloud())

    # Cleanup is CLEANUP -> requires approval; first call is pending, no delete.
    pending = wf.delete_snapshot("canary-01", ["snap-vol-a"])
    assert not pending.ok and pending.data["approval_state"] == "pending"
    assert not any(c[0] == "delete_snapshot" for c in cloud.calls)

    # Approve, then the delete actually runs.
    approvals.decide(pending.data["change_set_id"], "lead", approve=True, now=NOW)
    done = wf.delete_snapshot("canary-01", ["snap-vol-a"])
    assert done.ok
    assert done.data["deleted_snapshot_ids"] == ["snap-vol-a"]
    assert ("delete_snapshot", "snap-vol-a") in cloud.calls
