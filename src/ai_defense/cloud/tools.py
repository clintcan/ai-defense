"""Cloud discovery tools, registered into the toolset as dispatchable Executors.

Each factory takes a ``client_factory(credentials) -> AwsClient`` so the AWS
credential is resolved from the vault per call (via ``resolve_secret``) and used
to build the client for that call — the credential never lives on an adapter
instance and never reaches the planner. These are READ_ONLY tools (discovery),
so they run autonomously within policy.
"""

from __future__ import annotations

from collections.abc import Callable

from ..toolset.intents import ToolResult
from ..toolset.registry import ToolCapability, ToolSpec
from .aws import AwsAdapter
from .aws_client import AwsClient

EC2_DISCOVERY_TOOL = "aws.ec2.list_instances"
PATCH_STATE_TOOL = "aws.ssm.describe_patch_state"
LIGHTSAIL_DISCOVERY_TOOL = "aws.lightsail.list_instances"
SNAPSHOT_TOOL = "aws.snapshot_before_change"
SNAPSHOT_DELETE_TOOL = "aws.delete_snapshots"

ClientFactory = Callable[[dict], AwsClient]


def make_ec2_discovery_tool(client_factory: ClientFactory) -> ToolSpec:
    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credentials = resolve_secret(params["credential_ref"])
        adapter = AwsAdapter(client_factory(credentials))
        instances = adapter.list_instances(
            params["account"],
            {"ec2_filters": params.get("filters"), "instance_ids": params.get("instance_ids")},
        )
        return ToolResult(
            ok=True, tool=EC2_DISCOVERY_TOOL,
            summary=f"{len(instances)} instance(s) in account {params['account']}",
            data={"account": params["account"], "instances": instances},
        )

    return ToolSpec(
        name=EC2_DISCOVERY_TOOL,
        schema={
            "type": "object",
            "required": ["account", "credential_ref"],
            "properties": {
                "account": {"type": "string"},
                "credential_ref": {"type": "string"},
                "filters": {"type": "array"},
                "instance_ids": {"type": "array"},
            },
        },
        executor=_execute,
        capability=ToolCapability.READ_ONLY,
    )


def make_lightsail_discovery_tool(client_factory: ClientFactory) -> ToolSpec:
    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credentials = resolve_secret(params["credential_ref"])
        adapter = AwsAdapter(client_factory(credentials))
        instances = adapter.list_lightsail_instances(params["account"])
        return ToolResult(
            ok=True, tool=LIGHTSAIL_DISCOVERY_TOOL,
            summary=f"{len(instances)} Lightsail instance(s) in account {params['account']}",
            data={"account": params["account"], "instances": instances},
        )

    return ToolSpec(
        name=LIGHTSAIL_DISCOVERY_TOOL,
        schema={
            "type": "object",
            "required": ["account", "credential_ref"],
            "properties": {
                "account": {"type": "string"},
                "credential_ref": {"type": "string"},
            },
        },
        executor=_execute,
        capability=ToolCapability.READ_ONLY,
    )


def make_snapshot_tool(client_factory: ClientFactory) -> ToolSpec:
    """Protective snapshot-before-change (capability=PROTECTIVE, autonomous).

    Targets the instance being protected (which must be a registered, authorized
    asset). Supports EC2 (EBS snapshots) and Lightsail (instance snapshot)."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credentials = resolve_secret(params["credential_ref"])
        adapter = AwsAdapter(client_factory(credentials))
        record = adapter.snapshot_before_change(
            params["instance_id"],
            service=params.get("service", "ec2"),
            reason=params.get("reason", ""),
        )
        return ToolResult(
            ok=True, tool=SNAPSHOT_TOOL,
            summary=f"snapshot created for {params['instance_id']}: "
                    f"{record['snapshot_ids']}",
            data=record,
        )

    return ToolSpec(
        name=SNAPSHOT_TOOL,
        schema={
            "type": "object",
            "required": ["instance_id", "credential_ref"],
            "properties": {
                "instance_id": {"type": "string"},
                "service": {"type": "string", "enum": ["ec2", "lightsail"]},
                "credential_ref": {"type": "string"},
                "reason": {"type": "string"},
            },
        },
        executor=_execute,
        capability=ToolCapability.PROTECTIVE,
    )


def make_snapshot_delete_tool(client_factory: ClientFactory) -> ToolSpec:
    """Delete pre-change snapshots once a fix is stable (capability=MUTATING;
    dispatch under the CLEANUP action class so it is approval-gated — destroying
    a safety backup must be deliberate)."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credentials = resolve_secret(params["credential_ref"])
        adapter = AwsAdapter(client_factory(credentials))
        record = adapter.delete_snapshots(
            params["snapshot_ids"], service=params.get("service", "ec2"),
        )
        return ToolResult(
            ok=True, tool=SNAPSHOT_DELETE_TOOL,
            summary=f"deleted {len(record['deleted_snapshot_ids'])} snapshot(s)",
            data=record,
        )

    return ToolSpec(
        name=SNAPSHOT_DELETE_TOOL,
        schema={
            "type": "object",
            "required": ["snapshot_ids", "credential_ref"],
            "properties": {
                "instance_id": {"type": "string"},
                "snapshot_ids": {"type": "array"},
                "service": {"type": "string", "enum": ["ec2", "lightsail"]},
                "credential_ref": {"type": "string"},
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
    )


def make_patch_state_tool(client_factory: ClientFactory) -> ToolSpec:
    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credentials = resolve_secret(params["credential_ref"])
        adapter = AwsAdapter(client_factory(credentials))
        states = adapter.describe_patch_state(params["instance_ids"])
        noncompliant = [s["instance_id"] for s in states if not s["compliant"]]
        return ToolResult(
            ok=True, tool=PATCH_STATE_TOOL,
            summary=f"{len(states)} instance(s) scanned, {len(noncompliant)} non-compliant",
            data={"account": params.get("account"), "patch_states": states,
                  "noncompliant": noncompliant},
        )

    return ToolSpec(
        name=PATCH_STATE_TOOL,
        schema={
            "type": "object",
            "required": ["instance_ids", "credential_ref"],
            "properties": {
                "account": {"type": "string"},
                "credential_ref": {"type": "string"},
                "instance_ids": {"type": "array"},
            },
        },
        executor=_execute,
        capability=ToolCapability.READ_ONLY,
    )
