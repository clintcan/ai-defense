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
                "instance_id": i.get("InstanceId"),
                "state": (i.get("State") or {}).get("Name"),
                "platform": i.get("PlatformDetails") or i.get("Platform") or "linux",
                "name": tags.get("Name"),
                "private_ip": i.get("PrivateIpAddress"),
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

    # --- protective / write (not in the read-only slice) -----------------

    def snapshot_before_change(self, instance_id: str) -> dict:
        raise NotImplementedError("snapshot_before_change: protective slice, not yet implemented")

    def apply_patch_baseline(self, instance_ids: list[str], baseline: str) -> dict:
        raise NotImplementedError("apply_patch_baseline: write slice, not yet implemented")


def _isoformat(value) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else (value or None)
