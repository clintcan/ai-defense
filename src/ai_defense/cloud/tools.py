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
REGIONS_TOOL = "aws.list_regions"
SNAPSHOT_TOOL = "aws.snapshot_before_change"
SNAPSHOT_DELETE_TOOL = "aws.delete_snapshots"
PATCH_BASELINE_TOOL = "aws.ssm.apply_patch_baseline"

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


def make_regions_tool(client_factory: ClientFactory) -> ToolSpec:
    """List the regions available to a registered cloud account (read-only)."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credentials = resolve_secret(params["credential_ref"])
        adapter = AwsAdapter(client_factory(credentials))
        regions = adapter.list_regions(params["account"])
        return ToolResult(
            ok=True, tool=REGIONS_TOOL,
            summary=f"{len(regions['ec2'])} EC2 / {len(regions['lightsail'])} "
                    f"Lightsail region(s) for account {params['account']}",
            data=regions,
        )

    return ToolSpec(
        name=REGIONS_TOOL,
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


def make_lightsail_discovery_tool(client_factory: ClientFactory) -> ToolSpec:
    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credentials = resolve_secret(params["credential_ref"])
        adapter = AwsAdapter(client_factory(credentials))
        all_regions = bool(params.get("all_regions", True))   # Lightsail is region-scoped
        instances = adapter.list_lightsail_instances(params["account"], all_regions=all_regions)
        scope = "all regions" if all_regions else "default region"
        return ToolResult(
            ok=True, tool=LIGHTSAIL_DISCOVERY_TOOL,
            summary=f"{len(instances)} Lightsail instance(s) in account "
                    f"{params['account']} ({scope})",
            data={"account": params["account"], "instances": instances,
                  "all_regions": all_regions},
        )

    return ToolSpec(
        name=LIGHTSAIL_DISCOVERY_TOOL,
        schema={
            "type": "object",
            "required": ["account", "credential_ref"],
            "properties": {
                "account": {"type": "string"},
                "credential_ref": {"type": "string"},
                "all_regions": {"type": "boolean"},
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


def make_patch_baseline_tool(client_factory: ClientFactory) -> ToolSpec:
    """Apply an SSM patch baseline to EC2 instances (capability=MUTATING,
    approval-gated). Scans before installing unless scan_first is False. The
    blast radius is the number of target instances, surfaced to policy/approver."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credentials = resolve_secret(params["credential_ref"])
        adapter = AwsAdapter(client_factory(credentials))
        record = adapter.apply_patch_baseline(
            params["instance_ids"],
            params.get("baseline"),
            scan_first=params.get("scan_first", True),
        )
        return ToolResult(
            ok=record.get("command_id") is not None, tool=PATCH_BASELINE_TOOL,
            summary=f"patch baseline install dispatched to "
                    f"{len(record['instance_ids'])} instance(s) "
                    f"(command {record['command_id']})",
            data=record,
        )

    return ToolSpec(
        name=PATCH_BASELINE_TOOL,
        schema={
            "type": "object",
            "required": ["instance_ids", "credential_ref"],
            "properties": {
                "instance_ids": {"type": "array"},
                "baseline": {"type": "string"},
                "scan_first": {"type": "boolean"},
                "credential_ref": {"type": "string"},
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
        describe_blast_radius=lambda p: len(p.get("instance_ids", [])),
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
