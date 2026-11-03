"""AWS client seam for the adapter.

The adapter depends on this narrow Protocol, not on boto3 directly, so it is
testable without AWS or network and boto3 stays an optional extra. The real
``Boto3AwsClient`` imports boto3 lazily and builds a session from the credential
descriptor the toolset resolves from the vault at call time (never held by the
planner).

Credential modes (the descriptor is a dict):
  * ``{"profile": "<name>"}`` — use a named AWS CLI profile from the shared
    config/credentials files, exactly as the AWS CLI would (this is how it
    "piggybacks" on the CLI, including SSO and ``credential_process``).
  * ``{}`` or ``{"use_default_chain": true}`` — the default botocore provider
    chain: env vars, shared config (incl. SSO), container role, and the EC2/ECS
    instance role. No secret material is stored anywhere in that case.
  * ``{"aws_access_key_id": ..., "aws_secret_access_key": ..., ...}`` — explicit
    static keys (least preferred).
  * add ``{"role_arn": ...}`` to any of the above to assume a role on top of the
    base session (preferred for scoped, short-lived discovery credentials).

Read-only discovery (EC2 + SSM + Lightsail describe) plus a protective
snapshot-before-change path (EBS snapshots for EC2, the separate Lightsail
instance-snapshot API for Lightsail).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Protocol


class AwsClient(Protocol):
    def describe_instances(
        self, *, filters: list[dict] | None = None, instance_ids: list[str] | None = None,
    ) -> list[dict]:
        """Flattened EC2 instances (reservations already expanded)."""

    def describe_instance_patch_states(self, instance_ids: list[str]) -> list[dict]:
        """SSM patch-state summaries for the given instances."""

    def get_lightsail_instances(self, all_regions: bool = False) -> list[dict]:
        """Lightsail instances (separate service API). ``all_regions`` enumerates
        every Lightsail region instead of just the client's default region."""

    # --- protective (snapshot before change) ----------------------------

    def describe_instance_volumes(self, instance_id: str) -> list[dict]:
        """EBS volume ids attached to an EC2 instance."""

    def create_ebs_snapshot(self, volume_id: str, description: str,
                            tags: dict[str, str]) -> dict:
        """Create an EBS snapshot of a volume; returns at least a snapshot id."""

    def create_lightsail_snapshot(self, instance_name: str, snapshot_name: str) -> dict:
        """Create a Lightsail instance snapshot (separate service API)."""

    def delete_ebs_snapshot(self, snapshot_id: str) -> dict:
        """Delete an EBS snapshot (cleanup once a fix is confirmed stable)."""

    def delete_lightsail_snapshot(self, snapshot_name: str) -> dict:
        """Delete a Lightsail instance snapshot."""

    # --- write (patch) --------------------------------------------------

    def send_patch_command(self, instance_ids: list[str], operation: str,
                           baseline_id: str | None = None) -> dict:
        """Run SSM AWS-RunPatchBaseline on instances. ``operation`` is "Scan"
        (read-only) or "Install". Returns at least a command id + status."""


def _base_session(boto3, credentials: dict[str, Any], region: str | None):
    """Build the base boto3 Session from the credential descriptor.

    Profile and default-chain modes read the same sources as the AWS CLI, so the
    harness piggybacks on whatever the operator (or the instance role) already
    has configured — no secret material need be stored by us.
    """
    if credentials.get("profile"):
        return boto3.Session(profile_name=credentials["profile"], region_name=region)
    if credentials.get("aws_access_key_id"):
        return boto3.Session(
            aws_access_key_id=credentials["aws_access_key_id"],
            aws_secret_access_key=credentials.get("aws_secret_access_key"),
            aws_session_token=credentials.get("aws_session_token"),
            region_name=region,
        )
    # Default provider chain: env, shared config/credentials (incl. SSO,
    # credential_process), container role, EC2/ECS instance role — as the CLI.
    return boto3.Session(region_name=region)


class Boto3AwsClient:
    """Real client. Untested against live AWS in this scaffold; requires the
    ``aws`` extra (``pip install -e .[aws]``)."""

    def __init__(self, credentials: dict[str, Any] | None = None, *,
                 region: str | None = None) -> None:
        import boto3  # lazy: only needed when actually talking to AWS

        credentials = credentials or {}
        session = _base_session(boto3, credentials, region)

        # Optionally assume a role on top of whatever base identity resolved.
        if credentials.get("role_arn"):
            assumed = session.client("sts").assume_role(
                RoleArn=credentials["role_arn"],
                RoleSessionName=credentials.get("session_name", "ai-defense-discovery"),
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=assumed["AccessKeyId"],
                aws_secret_access_key=assumed["SecretAccessKey"],
                aws_session_token=assumed["SessionToken"],
                region_name=region,
            )

        self._session = session
        self._ec2 = session.client("ec2")
        self._ssm = session.client("ssm")
        self._lightsail = session.client("lightsail")

    def describe_instances(self, *, filters=None, instance_ids=None) -> list[dict]:
        kwargs: dict[str, Any] = {}
        if filters:
            kwargs["Filters"] = filters
        if instance_ids:
            kwargs["InstanceIds"] = instance_ids
        out: list[dict] = []
        paginator = self._ec2.get_paginator("describe_instances")
        for page in paginator.paginate(**kwargs):
            for reservation in page.get("Reservations", []):
                out.extend(reservation.get("Instances", []))
        return out

    def describe_instance_patch_states(self, instance_ids: list[str]) -> list[dict]:
        out: list[dict] = []
        paginator = self._ssm.get_paginator("describe_instance_patch_states")
        for page in paginator.paginate(InstanceIds=instance_ids):
            out.extend(page.get("InstancePatchStates", []))
        return out

    @staticmethod
    def _get_instances(client) -> list[dict]:
        # GetInstances is page-token based (no boto3 paginator).
        out: list[dict] = []
        token: str | None = None
        while True:
            kwargs = {"pageToken": token} if token else {}
            resp = client.get_instances(**kwargs)
            out.extend(resp.get("instances", []))
            token = resp.get("nextPageToken")
            if not token:
                return out

    def get_lightsail_instances(self, all_regions: bool = False) -> list[dict]:
        if not all_regions:
            return self._get_instances(self._lightsail)
        # Lightsail is region-scoped: enumerate every Lightsail region and query
        # each. Each instance already carries its region in location.regionName.
        regions = [r["name"] for r in self._lightsail.get_regions().get("regions", [])]
        out: list[dict] = []
        for region in regions:
            client = self._session.client("lightsail", region_name=region)
            out.extend(self._get_instances(client))
        return out

    def describe_instance_volumes(self, instance_id: str) -> list[dict]:
        resp = self._ec2.describe_volumes(
            Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}],
        )
        return resp.get("Volumes", [])

    def create_ebs_snapshot(self, volume_id, description, tags) -> dict:
        tag_specs = [{
            "ResourceType": "snapshot",
            "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
        }] if tags else []
        return self._ec2.create_snapshot(
            VolumeId=volume_id, Description=description, TagSpecifications=tag_specs,
        )

    def create_lightsail_snapshot(self, instance_name, snapshot_name) -> dict:
        return self._lightsail.create_instance_snapshot(
            instanceSnapshotName=snapshot_name, instanceName=instance_name,
        )

    def delete_ebs_snapshot(self, snapshot_id) -> dict:
        return self._ec2.delete_snapshot(SnapshotId=snapshot_id)

    def delete_lightsail_snapshot(self, snapshot_name) -> dict:
        return self._lightsail.delete_instance_snapshot(instanceSnapshotName=snapshot_name)

    def send_patch_command(self, instance_ids, operation, baseline_id=None) -> dict:
        params = {"Operation": [operation]}
        if baseline_id:
            params["BaselineOverride"] = [baseline_id]
        resp = self._ssm.send_command(
            DocumentName="AWS-RunPatchBaseline",
            InstanceIds=instance_ids,
            Parameters=params,
        )
        command = resp.get("Command", {})
        return {"command_id": command.get("CommandId"), "status": command.get("Status")}


def _normalize_credentials(creds: Any) -> dict:
    """Accept the vault-resolved credential in any convenient form and return the
    descriptor dict Boto3AwsClient expects.

    - dict                      -> used as-is
    - JSON string               -> parsed
    - plain string (e.g. "prod")-> treated as a CLI profile name
    """
    if isinstance(creds, dict):
        return creds
    if isinstance(creds, str):
        text = creds.strip()
        if text.startswith("{"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                pass
        return {"profile": text}
    raise TypeError(f"unsupported AWS credential type: {type(creds).__name__}")


def boto3_client_factory(default_region: str | None = None) -> Callable[[Any], Boto3AwsClient]:
    """Build a client factory for the cloud tools. The factory receives the
    vault-resolved credential, normalizes it (profile / JSON / dict), and
    constructs a Boto3AwsClient. Region comes from the credential descriptor if
    present, else ``default_region``."""

    def factory(creds: Any) -> Boto3AwsClient:
        descriptor = _normalize_credentials(creds)
        region = descriptor.get("region", default_region)
        return Boto3AwsClient(descriptor, region=region)

    return factory
