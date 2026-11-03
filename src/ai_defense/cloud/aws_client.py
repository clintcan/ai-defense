"""AWS client seam for the adapter.

The adapter depends on this narrow Protocol, not on boto3 directly, so it is
testable without AWS or network and boto3 stays an optional extra. The real
``Boto3AwsClient`` imports boto3 lazily and builds a session from credentials
resolved by the toolset from the vault at call time (never held by the planner).

This slice is read-only (EC2 describe + SSM patch-state describe).
"""

from __future__ import annotations

from typing import Any, Protocol


class AwsClient(Protocol):
    def describe_instances(
        self, *, filters: list[dict] | None = None, instance_ids: list[str] | None = None,
    ) -> list[dict]:
        """Flattened EC2 instances (reservations already expanded)."""

    def describe_instance_patch_states(self, instance_ids: list[str]) -> list[dict]:
        """SSM patch-state summaries for the given instances."""


class Boto3AwsClient:
    """Real client. Untested against live AWS in this scaffold; requires the
    ``aws`` extra (``pip install -e .[aws]``)."""

    def __init__(self, credentials: dict[str, Any], *, region: str) -> None:
        import boto3  # lazy: only needed when actually talking to AWS

        if credentials.get("role_arn"):
            sts = boto3.client("sts", region_name=region)
            assumed = sts.assume_role(
                RoleArn=credentials["role_arn"],
                RoleSessionName=credentials.get("session_name", "ai-defense-discovery"),
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=assumed["AccessKeyId"],
                aws_secret_access_key=assumed["SecretAccessKey"],
                aws_session_token=assumed["SessionToken"],
                region_name=region,
            )
        else:
            session = boto3.Session(
                aws_access_key_id=credentials.get("aws_access_key_id"),
                aws_secret_access_key=credentials.get("aws_secret_access_key"),
                aws_session_token=credentials.get("aws_session_token"),
                region_name=region,
            )
        self._ec2 = session.client("ec2")
        self._ssm = session.client("ssm")

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
