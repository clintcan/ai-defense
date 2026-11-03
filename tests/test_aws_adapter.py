"""AWS adapter + discovery tools, tested against a fake client (no AWS/network)."""

from datetime import UTC, datetime, timedelta

import pytest

from ai_defense.approval.gate import ApprovalGate
from ai_defense.audit.log import AuditLog
from ai_defense.cloud.aws import AwsAdapter
from ai_defense.cloud.tools import (
    EC2_DISCOVERY_TOOL,
    PATCH_STATE_TOOL,
    make_ec2_discovery_tool,
    make_patch_state_tool,
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
        "account": "123456789012", "instance_id": "i-001", "state": "running",
        "platform": "Linux/UNIX", "name": "web-1", "private_ip": "10.0.0.5",
        "tags": {"Name": "web-1", "env": "prod"},
    }
    assert out[1]["name"] is None and out[1]["tags"] == {}


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


def test_write_ops_not_implemented_in_readonly_slice():
    adapter = AwsAdapter(FakeAwsClient())
    with pytest.raises(NotImplementedError):
        adapter.snapshot_before_change("i-001")
    with pytest.raises(NotImplementedError):
        adapter.apply_patch_baseline(["i-001"], "pb-1")


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
    assets.register(Asset("123456789012", "cloud-account", "team", "web-prod",
                          Authorization("sig", "lead", NOW - timedelta(days=1),
                                        NOW + timedelta(days=30))))
    audit = AuditLog(clock=lambda: NOW)
    backend = _Backend()
    disp = Dispatcher(
        registry=reg, policy=PolicyEngine({"autonomous_action_classes": ["discovery", "scan"]}),
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
