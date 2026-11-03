"""AWS adapter — wraps ONLY reviewed, read-only discovery operations (this slice).

Normalizes raw AWS shapes into the stable dicts the rest of the system consumes.
Credentials are resolved by the toolset from the vault at call time and handed to
the client; the adapter never stores them and the planner never sees them.

Protective (snapshot) and write (apply-patch-baseline) operations are declared on
the base interface but intentionally not implemented in this read-only slice.
"""

from __future__ import annotations

from typing import Any

from .aws_client import AwsClient
from .base import CloudAdapter


def _tags_to_map(tags: list[dict] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tags or []) if "Key" in t}


class AwsAdapter(CloudAdapter):
    provider = "aws"

    def __init__(self, client: AwsClient) -> None:
        self._client = client

    # --- read-only -------------------------------------------------------

    def list_instances(self, account: str, filters: dict | None = None) -> list[dict]:
        raw = self._client.describe_instances(
            filters=(filters or {}).get("ec2_filters"),
            instance_ids=(filters or {}).get("instance_ids"),
        )
        out = []
        for i in raw:
            tags = _tags_to_map(i.get("Tags"))
            out.append({
                "account": account,
                "service": "ec2",
                "instance_id": i.get("InstanceId"),
                "state": (i.get("State") or {}).get("Name"),
                "platform": i.get("PlatformDetails") or i.get("Platform") or "linux",
                "name": tags.get("Name"),
                "private_ip": i.get("PrivateIpAddress"),
                "tags": tags,
            })
        return out

    def list_lightsail_instances(self, account: str) -> list[dict]:
        """Lightsail is a separate service; its instances never appear in EC2
        DescribeInstances. Normalized to the same stable instance dict, tagged
        ``service='lightsail'`` so downstream code can tell them apart (their
        patch/snapshot model differs from EC2)."""
        out = []
        for i in self._client.get_lightsail_instances():
            tags = {t["key"]: t.get("value") for t in (i.get("tags") or []) if "key" in t}
            out.append({
                "account": account,
                "service": "lightsail",
                "instance_id": i.get("name"),          # Lightsail keys on name
                "arn": i.get("arn"),
                "state": (i.get("state") or {}).get("name"),
                "platform": i.get("blueprintId") or "linux",
                "name": i.get("name"),
                "private_ip": i.get("privateIpAddress"),
                "public_ip": i.get("publicIpAddress"),
                "tags": tags,
            })
        return out

    def describe_patch_state(self, instance_ids: list[str]) -> list[dict]:
        if not instance_ids:
            return []
        raw = self._client.describe_instance_patch_states(instance_ids)
        out = []
        for p in raw:
            missing = int(p.get("MissingCount", 0))
            failed = int(p.get("FailedCount", 0))
            out.append({
                "instance_id": p.get("InstanceId"),
                "baseline_id": p.get("BaselineId"),
                "installed": int(p.get("InstalledCount", 0)),
                "missing": missing,
                "failed": failed,
                "pending_reboot": int(p.get("InstalledPendingRebootCount", 0)),
                "operation_end_time": _isoformat(p.get("OperationEndTime")),
                "compliant": missing == 0 and failed == 0,
            })
        return out

    def blast_radius(self, op: str, params: dict[str, Any]) -> int:
        # Read-only discovery changes nothing.
        if op in ("list_instances", "describe_patch_state"):
            return 0
        ids = params.get("instance_ids") or params.get("targets") or []
        return len(ids)

    # --- protective (snapshot before change) -----------------------------

    def snapshot_before_change(self, instance_id: str, *, service: str = "ec2",
                               reason: str = "") -> dict:
        """Snapshot an instance before a change so the change is reversible.

        EC2 snapshots every attached EBS volume; Lightsail uses its own
        instance-snapshot API. Returns a normalized record with the created
        snapshot id(s) and a rollback hint, suitable for the audit log and a
        RemediationItem's rollback payload.
        """
        if service == "lightsail":
            return self._snapshot_lightsail(instance_id, reason)
        if service == "ec2":
            return self._snapshot_ec2(instance_id, reason)
        raise ValueError(f"unsupported service for snapshot: {service!r}")

    def _snapshot_ec2(self, instance_id: str, reason: str) -> dict:
        volumes = self._client.describe_instance_volumes(instance_id)
        volume_ids = [v["VolumeId"] for v in volumes if "VolumeId" in v]
        if not volume_ids:
            raise ValueError(f"no EBS volumes found for instance {instance_id}")
        snapshots = []
        for vid in volume_ids:
            snap = self._client.create_ebs_snapshot(
                vid,
                f"ai-defense pre-change snapshot of {instance_id} ({reason})"[:255],
                {"ai-defense": "pre-change", "instance-id": instance_id},
            )
            snapshots.append({"volume_id": vid, "snapshot_id": snap.get("SnapshotId")})
        return {
            "service": "ec2", "instance_id": instance_id, "snapshots": snapshots,
            "snapshot_ids": [s["snapshot_id"] for s in snapshots],
            "rollback": f"restore EC2 instance {instance_id} from EBS snapshot(s) "
                        f"{[s['snapshot_id'] for s in snapshots]}",
        }

    def _snapshot_lightsail(self, instance_name: str, reason: str) -> dict:
        snapshot_name = f"ai-defense-{instance_name}-prechange"
        self._client.create_lightsail_snapshot(instance_name, snapshot_name)
        return {
            "service": "lightsail", "instance_id": instance_name,
            "snapshot_ids": [snapshot_name],
            "rollback": f"restore Lightsail instance {instance_name} from snapshot "
                        f"{snapshot_name}",
        }

    def delete_snapshots(self, snapshot_ids: list[str], *, service: str = "ec2") -> dict:
        """Delete pre-change snapshots once a fix is confirmed stable.

        Deliberately separate from taking a snapshot, and dispatched under the
        approval-gated CLEANUP action class so a safety backup is never destroyed
        silently."""
        deleted = []
        for sid in snapshot_ids:
            if service == "lightsail":
                self._client.delete_lightsail_snapshot(sid)
            elif service == "ec2":
                self._client.delete_ebs_snapshot(sid)
            else:
                raise ValueError(f"unsupported service for snapshot delete: {service!r}")
            deleted.append(sid)
        return {"service": service, "deleted_snapshot_ids": deleted}

    # --- write (patch) ---------------------------------------------------

    def apply_patch_baseline(self, instance_ids: list[str], baseline: str | None = None,
                             *, scan_first: bool = True) -> dict:
        """Apply an SSM patch baseline to EC2 instances via AWS-RunPatchBaseline.

        Mirrors the SSH executor's dry-run-first safety: an SSM **Scan**
        (read-only, reports what's missing) runs before the **Install** unless
        ``scan_first`` is False. Rollback is via the pre-change snapshot the
        remediation workflow takes first (a baseline install is not trivially
        reversible on its own)."""
        if not instance_ids:
            raise ValueError("apply_patch_baseline requires at least one instance")

        scan_command_id = None
        if scan_first:
            scan = self._client.send_patch_command(instance_ids, "Scan", baseline)
            scan_command_id = scan.get("command_id")

        install = self._client.send_patch_command(instance_ids, "Install", baseline)
        return {
            "service": "ec2",
            "operation": "Install",
            "instance_ids": list(instance_ids),
            "baseline": baseline,
            "command_id": install.get("command_id"),
            "status": install.get("status"),
            "scan_command_id": scan_command_id,
            "rollback": "restore affected instances from the pre-change snapshot(s) "
                        "taken by the remediation workflow",
        }


def _isoformat(value) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else (value or None)
