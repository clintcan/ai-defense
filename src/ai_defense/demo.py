"""Demo backends and a scripted end-to-end run — no external infra required.

Everything here is simulation: an in-memory vault, a simulated SSH transport
(nothing leaves the process), and a canned AWS client. It exists so the whole
pipeline — onboarding, scan, plan, approval gate, dry-run, remediation, audit —
can be driven and watched locally. Production wiring swaps these for the real
vault backend, a paramiko transport, and boto3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ssh.executor import CommandOutput

# A policy mirroring config/policy.example.yaml, inline so the demo needs no file.
DEMO_POLICY: dict[str, Any] = {
    "autonomous_action_classes": ["discovery", "scan", "protective"],
    "blast_radius_caps": {"patch_canary": 3, "patch_fleet": 500},
    "rate_limits": {"per_host_changes_per_hour": 5, "fleet_concurrency": 25},
    "approvals": {
        "patch_canary": {"required": 1},
        "patch_fleet": {"required": 2, "after": "canary_health_ok"},
        "cleanup": {"required": 1},
        "onboard": {"required": 1},
    },
}

# Secrets the "operator" has pre-loaded into the vault (values are fake).
DEMO_SECRETS: dict[str, Any] = {
    "ssh-key/vps-demo-01": "DEMO-SSH-PRIVATE-KEY",
    "aws/demo": {"profile": "demo"},
}


class DemoSecretsBackend:
    """In-memory vault. Raises on unknown refs, like a real backend would."""

    def __init__(self, secrets: dict[str, Any] | None = None) -> None:
        self._secrets = dict(secrets or DEMO_SECRETS)

    def resolve(self, ref: str) -> Any:
        return self._secrets[ref]        # KeyError if missing -> fail safe

    def audit_access(self, ref: str, *, actor: str, reason: str) -> None:
        pass

    def put(self, ref: str, value: Any) -> None:
        self._secrets[ref] = value


class SimulatedSSHTransport:
    """Pretends to run argv over SSH. Returns success and echoes the command;
    nothing actually connects anywhere."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def run(self, host, argv, *, key, timeout, user="root", port=22) -> CommandOutput:
        self.calls.append((host, user, port, tuple(argv)))
        return CommandOutput(0, f"[sim] {user}@{host}:{port} ran: {' '.join(argv)}", "")


class DemoAwsClient:
    """Canned AWS responses so the cloud tools run without boto3 or AWS."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def describe_instances(self, *, filters=None, instance_ids=None):
        return [{"InstanceId": "i-0demo", "State": {"Name": "running"},
                 "PlatformDetails": "Linux/UNIX", "PrivateIpAddress": "10.0.0.9",
                 "Tags": [{"Key": "Name", "Value": "demo-ec2"}]}]

    def describe_instance_patch_states(self, instance_ids):
        return [{"InstanceId": i, "BaselineId": "pb-demo", "InstalledCount": 90,
                 "MissingCount": 2, "FailedCount": 0, "InstalledPendingRebootCount": 0}
                for i in instance_ids]

    def get_lightsail_instances(self, all_regions=False):
        insts = [{"name": "ls-demo", "state": {"name": "running"},
                  "blueprintId": "ubuntu_22_04", "publicIpAddress": "203.0.113.7",
                  "location": {"regionName": "us-east-1"},
                  "tags": [{"key": "env", "value": "demo"}]}]
        if all_regions:   # pretend a second region has one too
            insts.append({"name": "ls-demo-eu", "state": {"name": "running"},
                          "blueprintId": "debian_12", "publicIpAddress": "198.51.100.8",
                          "location": {"regionName": "eu-west-1"}, "tags": []})
        return insts

    def describe_ec2_regions(self):
        return ["us-east-1", "us-west-2", "eu-west-1"]

    def get_lightsail_regions(self):
        return ["us-east-1", "eu-west-1", "ap-southeast-1"]

    def describe_instance_volumes(self, instance_id):
        self.calls.append(("describe_volumes", instance_id))
        return [{"VolumeId": "vol-demo"}]

    def create_ebs_snapshot(self, volume_id, description, tags):
        self.calls.append(("create_snapshot", volume_id))
        return {"SnapshotId": f"snap-{volume_id}"}

    def delete_ebs_snapshot(self, snapshot_id):
        self.calls.append(("delete_snapshot", snapshot_id))
        return {}

    def create_lightsail_snapshot(self, n, s):
        return {"operations": [{"status": "Started"}]}

    def delete_lightsail_snapshot(self, n):
        return {}

    def send_patch_command(self, instance_ids, operation, baseline_id=None):
        self.calls.append(("send_patch_command", tuple(instance_ids), operation))
        return {"command_id": f"cmd-{operation.lower()}", "status": "Pending"}


class DemoInspector:
    """Read-only host inspector: reports a vulnerable openssl on every host, and
    a (now past-standard-support) Ubuntu 18.04 so the upgrade preflight has
    something to recommend."""

    def collect(self, asset_id: str) -> dict:
        return {"installed_packages": {"openssl": "3.0.5", "bash": "5.1"},
                "applied_patches": ["KB-1001"], "misconfigurations": [],
                "os_release": {"ID": "ubuntu", "VERSION_ID": "18.04",
                               "VERSION_CODENAME": "bionic"}}

    def collect_upgrade_state(self, asset_id: str) -> dict:
        return {"reboot_required": False, "disk_free_mb": 20480,
                "held_packages": [], "broken_packages_report": ""}


@dataclass(frozen=True)
class DemoStep:
    title: str
    detail: str


def scripted_demo() -> list[DemoStep]:
    """Drive the full lifecycle on the demo engine and return printable steps.

    Onboard a VPS (approval-gated) -> scan -> plan -> remediate the top finding
    (approval-gated, dry-run first) -> show the audit tail. Human approvals are
    auto-approved here and labelled as such.
    """
    from .composition import build_demo_engine

    eng = build_demo_engine()
    steps: list[DemoStep] = []

    # 1. Onboard a VPS through the approval-gated asset.register tool.
    pending = eng.onboard_ssh(
        asset_id="vps-demo-01", host="198.51.100.20", key_ref="ssh-key/vps-demo-01",
        owner="ops", environment="prod", granted_by="operator", user="ubuntu", port=22,
    )
    cs = pending.data.get("change_set_id")
    steps.append(DemoStep(
        "Onboard vps-demo-01 (asset.register)",
        f"first dispatch -> {pending.summary} [approval gate held it; "
        f"change-set {cs}]"))
    eng.approve(cs, "secops-lead")
    confirmed = eng.onboard_ssh(
        asset_id="vps-demo-01", host="198.51.100.20", key_ref="ssh-key/vps-demo-01",
        owner="ops", environment="prod", granted_by="operator", user="ubuntu", port=22,
    )
    steps.append(DemoStep("  (operator approved)",
                          f"second dispatch -> ok={confirmed.ok}: {confirmed.summary}"))

    # 2. Scan the host (read-only, autonomous).
    inventory = eng.scan(["vps-demo-01"])
    pkgs = inventory[0].installed_packages
    steps.append(DemoStep("Scan vps-demo-01 (read-only)",
                          f"observed packages: {pkgs}"))

    # 3. Plan against the advisory feed.
    plan = eng.plan(inventory)
    steps.append(DemoStep(
        "Plan remediation (KEV-first)",
        " | ".join(f"{it.cve_id}:{it.kind.value}(prio {it.priority:.0f})" for it in plan)
        or "no findings"))

    # 4. Remediate the top patch item (snapshot disabled: a plain VPS, no cloud
    #    snapshot in this demo). Approval-gated, dry-run first.
    patch_items = [it for it in plan if it.intent is not None]
    if patch_items:
        item = patch_items[0]
        r1 = eng.remediate(item, snapshot=False)
        cs2 = r1.patch.data.get("change_set_id")
        steps.append(DemoStep(
            f"Remediate {item.cve_id} on {item.asset_id}",
            f"status={r1.status} [approval gate held it; change-set {cs2}]"))
        eng.approve(cs2, "secops-lead")
        r2 = eng.remediate(item, snapshot=False)
        steps.append(DemoStep("  (operator approved)",
                              f"status={r2.status}: {r2.patch.summary}"))

    # 5. Audit tail + chain integrity.
    tail = eng.audit_tail(8)
    steps.append(DemoStep(
        f"Audit log (verify={eng.audit_ok()})",
        "\n".join(f"  - {r.event}: {r.payload.get('tool', r.payload.get('reason', ''))}"
                  for r in tail)))
    return steps
