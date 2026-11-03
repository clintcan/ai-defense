"""AWS adapter + discovery tools, tested against a fake client (no AWS/network)."""

from datetime import UTC, datetime, timedelta

import pytest

from ai_defense.approval.gate import ApprovalGate
from ai_defense.audit.log import AuditLog
from ai_defense.cloud.aws import AwsAdapter
from ai_defense.cloud.tools import (
    EC2_DISCOVERY_TOOL,
    LIGHTSAIL_DISCOVERY_TOOL,
    PATCH_BASELINE_TOOL,
    PATCH_STATE_TOOL,
    SNAPSHOT_TOOL,
    make_ec2_discovery_tool,
    make_lightsail_discovery_tool,
    make_patch_baseline_tool,
    make_patch_state_tool,
    make_snapshot_tool,
)
from ai_defense.registry.assets import Asset, AssetRegistry, Authorization
from ai_defense.toolset.dispatch import Dispatcher
from ai_defense.toolset.intents import ActionClass, Intent
from ai_defense.toolset.policy import PolicyEngine
from ai_defense.toolset.registry import ToolRegistry
from ai_defense.vault.vault import SecretsBackend, Vault

NOW = datetime(2026, 11, 3, tzinfo=UTC)
AWS_SECRET = "AKIA-FAKE/secret-material"


class FakeAwsClient:
    def __init__(self):
        self.calls = []

    def describe_instances(self, *, filters=None, instance_ids=None):
        self.calls.append(("describe_instances", filters, instance_ids))
        return [
            {
                "InstanceId": "i-001",
                "State": {"Name": "running"},
                "PlatformDetails": "Linux/UNIX",
                "PrivateIpAddress": "10.0.0.5",
                "Tags": [{"Key": "Name", "Value": "web-1"}, {"Key": "env", "Value": "prod"}],
            },
            {
                "InstanceId": "i-002",
                "State": {"Name": "stopped"},
                "PlatformDetails": "Linux/UNIX",
                "Tags": [],
            },
        ]

    def get_lightsail_instances(self, all_regions=False):
        self.calls.append(("get_lightsail_instances", all_regions))
        return [
            {
                "name": "ls-blog-1",
                "arn": "arn:aws:lightsail:us-east-1:123456789012:Instance/abc",
                "state": {"name": "running"},
                "blueprintId": "ubuntu_22_04",
                "location": {"regionName": "us-east-1"},
                "privateIpAddress": "172.26.0.5",
                "publicIpAddress": "3.4.5.6",
                "tags": [{"key": "env", "value": "prod"}, {"key": "owner"}],
            },
        ]

    # --- protective snapshot fakes --------------------------------------

    def describe_instance_volumes(self, instance_id):
        self.calls.append(("describe_instance_volumes", instance_id))
        if instance_id == "i-novol":
            return []
        return [{"VolumeId": "vol-aaa"}, {"VolumeId": "vol-bbb"}]

    def create_ebs_snapshot(self, volume_id, description, tags):
        self.calls.append(("create_ebs_snapshot", volume_id, description, tags))
        return {"SnapshotId": f"snap-{volume_id}"}

    def create_lightsail_snapshot(self, instance_name, snapshot_name):
        self.calls.append(("create_lightsail_snapshot", instance_name, snapshot_name))
        return {"operations": [{"status": "Started"}]}

    def send_patch_command(self, instance_ids, operation, baseline_id=None):
        self.calls.append(("send_patch_command", tuple(instance_ids), operation, baseline_id))
        return {"command_id": f"cmd-{operation.lower()}", "status": "Pending"}

    def describe_instance_patch_states(self, instance_ids):
        self.calls.append(("describe_instance_patch_states", instance_ids))
        return [
            {"InstanceId": "i-001", "BaselineId": "pb-1", "InstalledCount": 100,
             "MissingCount": 0, "FailedCount": 0, "InstalledPendingRebootCount": 0,
             "OperationEndTime": NOW},
            {"InstanceId": "i-002", "BaselineId": "pb-1", "InstalledCount": 90,
             "MissingCount": 3, "FailedCount": 1, "InstalledPendingRebootCount": 2,
             "OperationEndTime": NOW},
        ]


# --- adapter normalization ----------------------------------------------

def test_list_instances_normalizes():
    adapter = AwsAdapter(FakeAwsClient())
    out = adapter.list_instances("123456789012")
    assert out[0] == {
        "account": "123456789012", "service": "ec2", "instance_id": "i-001",
        "state": "running", "platform": "Linux/UNIX", "name": "web-1",
        "private_ip": "10.0.0.5", "tags": {"Name": "web-1", "env": "prod"},
    }
    assert out[1]["name"] is None and out[1]["tags"] == {}


def test_list_lightsail_instances_normalizes():
    adapter = AwsAdapter(FakeAwsClient())
    out = adapter.list_lightsail_instances("123456789012")
    assert len(out) == 1
    inst = out[0]
    assert inst["service"] == "lightsail"
    assert inst["instance_id"] == "ls-blog-1"       # Lightsail keys on name
    assert inst["state"] == "running"
    assert inst["platform"] == "ubuntu_22_04"
    assert inst["public_ip"] == "3.4.5.6"
    assert inst["region"] == "us-east-1"            # from location.regionName
    assert inst["tags"] == {"env": "prod", "owner": None}   # valueless tag kept


class _MultiRegionLightsail(FakeAwsClient):
    """Enumerates regions and returns an instance per region (like all_regions)."""

    def get_lightsail_instances(self, all_regions=False):
        self.calls.append(("get_lightsail_instances", all_regions))
        if not all_regions:
            return [{"name": "ls-use1", "location": {"regionName": "us-east-1"},
                     "state": {"name": "running"}, "tags": []}]
        return [{"name": "ls-use1", "location": {"regionName": "us-east-1"},
                 "state": {"name": "running"}, "tags": []},
                {"name": "ls-euw1", "location": {"regionName": "eu-west-1"},
                 "state": {"name": "running"}, "tags": []},
                {"name": "ls-apse1", "location": {"regionName": "ap-southeast-1"},
                 "state": {"name": "running"}, "tags": []}]


def test_list_lightsail_all_regions():
    adapter = AwsAdapter(_MultiRegionLightsail())
    default = adapter.list_lightsail_instances("acct")
    assert {i["region"] for i in default} == {"us-east-1"}            # one region
    everywhere = adapter.list_lightsail_instances("acct", all_regions=True)
    assert {i["region"] for i in everywhere} == {
        "us-east-1", "eu-west-1", "ap-southeast-1"}                   # all regions


def test_describe_patch_state_compliance_flag():
    adapter = AwsAdapter(FakeAwsClient())
    states = adapter.describe_patch_state(["i-001", "i-002"])
    by_id = {s["instance_id"]: s for s in states}
    assert by_id["i-001"]["compliant"] is True
    assert by_id["i-002"]["compliant"] is False   # missing=3, failed=1
    assert by_id["i-002"]["pending_reboot"] == 2
    assert by_id["i-001"]["operation_end_time"] == NOW.isoformat()


def test_describe_patch_state_empty_is_noop():
    client = FakeAwsClient()
    assert AwsAdapter(client).describe_patch_state([]) == []
    assert client.calls == []                      # no API call for an empty list


def test_blast_radius_zero_for_readonly():
    adapter = AwsAdapter(FakeAwsClient())
    assert adapter.blast_radius("list_instances", {}) == 0
    assert adapter.blast_radius("apply_patch_baseline", {"instance_ids": ["a", "b"]}) == 2


# --- protective snapshot ------------------------------------------------

def test_snapshot_ec2_snapshots_every_volume():
    adapter = AwsAdapter(FakeAwsClient())
    rec = adapter.snapshot_before_change("i-001", service="ec2", reason="CVE-1")
    assert rec["service"] == "ec2"
    assert rec["snapshot_ids"] == ["snap-vol-aaa", "snap-vol-bbb"]
    assert "i-001" in rec["rollback"]


def test_snapshot_ec2_no_volumes_raises():
    adapter = AwsAdapter(FakeAwsClient())
    with pytest.raises(ValueError, match="no EBS volumes"):
        adapter.snapshot_before_change("i-novol", service="ec2")


def test_snapshot_lightsail_uses_its_own_api():
    adapter = AwsAdapter(FakeAwsClient())
    rec = adapter.snapshot_before_change("ls-blog-1", service="lightsail")
    assert rec["service"] == "lightsail"
    assert rec["snapshot_ids"] == ["ai-defense-ls-blog-1-prechange"]


def test_snapshot_unsupported_service_raises():
    adapter = AwsAdapter(FakeAwsClient())
    with pytest.raises(ValueError, match="unsupported service"):
        adapter.snapshot_before_change("i-001", service="rds")


# --- dispatcher integration ---------------------------------------------

class _Backend(SecretsBackend):
    def __init__(self):
        self.access_log = []

    def resolve(self, ref):
        return AWS_SECRET

    def audit_access(self, ref, *, actor, reason):
        self.access_log.append((ref, actor, reason))


def _dispatcher_with(tool):
    reg = ToolRegistry()
    reg.register(tool)
    assets = AssetRegistry()
    auth = Authorization("sig", "lead", NOW - timedelta(days=1), NOW + timedelta(days=30))
    assets.register(Asset("123456789012", "cloud-account", "team", "web-prod", auth))
    assets.register(Asset("i-001", "ec2-instance", "team", "web-prod", auth))
    audit = AuditLog(clock=lambda: NOW)
    backend = _Backend()
    disp = Dispatcher(
        registry=reg,
        policy=PolicyEngine({"autonomous_action_classes":
                             ["discovery", "scan", "protective"]}),
        assets=assets, approvals=ApprovalGate(), vault=Vault(backend), audit=audit,
        clock=lambda: NOW,
    )
    return disp, audit, backend


def test_ec2_discovery_runs_autonomously():
    fake = FakeAwsClient()
    disp, audit, backend = _dispatcher_with(make_ec2_discovery_tool(lambda creds: fake))
    intent = Intent(
        tool=EC2_DISCOVERY_TOOL,
        params={"account": "123456789012", "credential_ref": "aws/discovery-role"},
        targets=["123456789012"], action_class=ActionClass.DISCOVERY, reason="inventory",
    )
    res = disp.dispatch(intent)
    assert res.ok
    assert len(res.data["instances"]) == 2
    assert res.data["instances"][0]["instance_id"] == "i-001"
    # credential was resolved via the vault (audited access), never exposed
    assert backend.access_log and backend.access_log[0][0] == "aws/discovery-role"
    assert AWS_SECRET not in str(res.data)
    blob = "".join(str(r.payload) for r in audit.records())
    assert AWS_SECRET not in blob


def test_patch_state_tool_flags_noncompliant():
    fake = FakeAwsClient()
    disp, _, _ = _dispatcher_with(make_patch_state_tool(lambda creds: fake))
    intent = Intent(
        tool=PATCH_STATE_TOOL,
        params={"account": "123456789012", "credential_ref": "aws/discovery-role",
                "instance_ids": ["i-001", "i-002"]},
        targets=["123456789012"], action_class=ActionClass.SCAN, reason="patch audit",
    )
    res = disp.dispatch(intent)
    assert res.ok
    assert res.data["noncompliant"] == ["i-002"]


def test_discovery_requires_registered_account():
    fake = FakeAwsClient()
    disp, _, _ = _dispatcher_with(make_ec2_discovery_tool(lambda creds: fake))
    intent = Intent(
        tool=EC2_DISCOVERY_TOOL,
        params={"account": "999999999999", "credential_ref": "aws/discovery-role"},
        targets=["999999999999"], action_class=ActionClass.DISCOVERY, reason="x",
    )
    res = disp.dispatch(intent)
    assert not res.ok and "authorization" in res.data["reason"]


def test_lightsail_discovery_runs_autonomously():
    fake = FakeAwsClient()
    disp, audit, backend = _dispatcher_with(make_lightsail_discovery_tool(lambda creds: fake))
    intent = Intent(
        tool=LIGHTSAIL_DISCOVERY_TOOL,
        params={"account": "123456789012", "credential_ref": "aws/discovery-role"},
        targets=["123456789012"], action_class=ActionClass.DISCOVERY, reason="inventory",
    )
    res = disp.dispatch(intent)
    assert res.ok
    assert res.data["instances"][0]["service"] == "lightsail"
    assert res.data["instances"][0]["instance_id"] == "ls-blog-1"
    # credential resolved via vault and never exposed
    assert backend.access_log and backend.access_log[0][0] == "aws/discovery-role"
    assert AWS_SECRET not in str(res.data)


def test_snapshot_tool_runs_autonomously_as_protective():
    fake = FakeAwsClient()
    disp, audit, backend = _dispatcher_with(make_snapshot_tool(lambda creds: fake))
    intent = Intent(
        tool=SNAPSHOT_TOOL,
        params={"instance_id": "i-001", "credential_ref": "aws/snapshot-role",
                "service": "ec2", "reason": "pre CVE-2026-1 patch"},
        targets=["i-001"], action_class=ActionClass.PROTECTIVE, reason="pre-change backup",
    )
    res = disp.dispatch(intent)
    assert res.ok                                      # no approval needed (protective)
    assert res.data["snapshot_ids"] == ["snap-vol-aaa", "snap-vol-bbb"]
    assert backend.access_log[0][0] == "aws/snapshot-role"
    blob = "".join(str(r.payload) for r in audit.records())
    assert AWS_SECRET not in blob


def test_snapshot_tool_cannot_be_mislabeled_as_mutating():
    # The PROTECTIVE capability must not run under a mutating action class.
    fake = FakeAwsClient()
    disp, _, _ = _dispatcher_with(make_snapshot_tool(lambda creds: fake))
    intent = Intent(
        tool=SNAPSHOT_TOOL,
        params={"instance_id": "i-001", "credential_ref": "aws/snapshot-role"},
        targets=["i-001"], action_class=ActionClass.PATCH_FLEET, reason="x",
    )
    res = disp.dispatch(intent)
    assert not res.ok and "may not run under action class" in res.summary


# --- apply_patch_baseline (write) ---------------------------------------

def test_patch_baseline_scans_before_install():
    client = FakeAwsClient()
    rec = AwsAdapter(client).apply_patch_baseline(["i-001", "i-002"], "pb-9")
    ops = [c for c in client.calls if c[0] == "send_patch_command"]
    assert ops[0][2] == "Scan" and ops[1][2] == "Install"       # scan first
    assert rec["command_id"] == "cmd-install"
    assert rec["scan_command_id"] == "cmd-scan"
    assert rec["instance_ids"] == ["i-001", "i-002"]
    assert "snapshot" in rec["rollback"]


def test_patch_baseline_scan_first_false_skips_scan():
    client = FakeAwsClient()
    AwsAdapter(client).apply_patch_baseline(["i-001"], None, scan_first=False)
    ops = [c for c in client.calls if c[0] == "send_patch_command"]
    assert len(ops) == 1 and ops[0][2] == "Install"


def test_patch_baseline_empty_raises():
    with pytest.raises(ValueError, match="at least one instance"):
        AwsAdapter(FakeAwsClient()).apply_patch_baseline([])


def _patch_dispatcher(policy_cfg):
    fake = FakeAwsClient()
    reg = ToolRegistry()
    reg.register(make_patch_baseline_tool(lambda creds: fake))
    assets = AssetRegistry()
    auth = Authorization("sig", "lead", NOW - timedelta(days=1), NOW + timedelta(days=30))
    for iid in ["i-001", "i-002", "i-003", "i-004"]:
        assets.register(Asset(iid, "ec2-instance", "team", "web-prod", auth))
    approvals = ApprovalGate()
    disp = Dispatcher(
        registry=reg, policy=PolicyEngine(policy_cfg), assets=assets,
        approvals=approvals, vault=Vault(_Backend()), audit=AuditLog(clock=lambda: NOW),
        clock=lambda: NOW,
    )
    return disp, approvals, fake


def test_patch_baseline_pending_then_applied():
    disp, approvals, fake = _patch_dispatcher({
        "blast_radius_caps": {"patch_canary": 3},
        "approvals": {"patch_canary": {"required": 1}},
    })
    intent = Intent(
        tool=PATCH_BASELINE_TOOL,
        params={"instance_ids": ["i-001", "i-002"], "credential_ref": "aws/patch-role",
                "baseline": "pb-9"},
        targets=["i-001", "i-002"], action_class=ActionClass.PATCH_CANARY,
        reason="CVE-2026-9",
    )
    pending = disp.dispatch(intent)
    assert not pending.ok and pending.data["approval_state"] == "pending"
    assert pending.data["blast_radius"] == 2                     # instance count
    assert not any(c[0] == "send_patch_command" for c in fake.calls)

    approvals.decide(pending.data["change_set_id"], "lead", approve=True, now=NOW)
    res = disp.dispatch(intent)
    assert res.ok
    assert res.data["command_id"] == "cmd-install"


def test_patch_baseline_blast_radius_cap_denies():
    disp, approvals, fake = _patch_dispatcher({
        "blast_radius_caps": {"patch_canary": 3},
        "approvals": {"patch_canary": {"required": 1}},
    })
    intent = Intent(
        tool=PATCH_BASELINE_TOOL,
        params={"instance_ids": ["i-001", "i-002", "i-003", "i-004"],
                "credential_ref": "aws/patch-role"},
        targets=["i-001", "i-002", "i-003", "i-004"],
        action_class=ActionClass.PATCH_CANARY, reason="x",
    )
    res = disp.dispatch(intent)
    assert not res.ok and "blast radius" in res.data["reason"]
    assert not any(c[0] == "send_patch_command" for c in fake.calls)
