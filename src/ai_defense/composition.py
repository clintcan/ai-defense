"""Composition root: wire the whole engine from parts.

``build_demo_engine`` assembles a fully runnable Engine with the demo backends
(no external infra). A production ``build_engine`` would differ only in the
backends it injects (real vault, paramiko transport, boto3 client, a DB-backed
audit store) — the wiring is the same.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .advisories import DEMO_ADVISORIES
from .approval.gate import ApprovalGate, ApprovalState
from .audit.log import AuditLog, AuditRecord
from .cloud.tools import (
    make_ec2_discovery_tool,
    make_lightsail_discovery_tool,
    make_patch_baseline_tool,
    make_patch_state_tool,
    make_snapshot_delete_tool,
    make_snapshot_tool,
)
from .demo import (
    DEMO_POLICY,
    DemoAwsClient,
    DemoInspector,
    DemoSecretsBackend,
    SimulatedSSHTransport,
)
from .onboarding import build_ssh_asset, make_asset_register_tool
from .registry.assets import Asset, AssetRegistry, Authorization
from .scanner.scanner import AuthenticatedScanner, HostFindings
from .ssh.executor import SSHExecutor
from .ssh.tools import make_security_update_tool, registry_connection_resolver
from .toolset.dispatch import Dispatcher
from .toolset.intents import ActionClass, Intent, ToolResult
from .toolset.policy import PolicyEngine
from .toolset.ratelimit import RateLimiter
from .toolset.registry import ToolRegistry
from .vault.vault import Vault
from .vuln.feeds import Advisory, StaticAdvisoryFeed
from .vuln.planner import RemediationItem, RemediationPlanner
from .vuln.workflow import RemediationWorkflow, WorkflowResult


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Engine:
    """The wired system. High-level methods are thin wrappers over the toolset,
    so every call still passes through policy, authorization, approval, rate
    limits, redaction, and the audit log."""

    registry: AssetRegistry
    dispatcher: Dispatcher
    approvals: ApprovalGate
    audit: AuditLog
    scanner: AuthenticatedScanner
    planner: RemediationPlanner
    workflow: RemediationWorkflow
    feed: StaticAdvisoryFeed
    clock: Callable[[], datetime] = _utcnow

    # -- inventory --------------------------------------------------------
    def list_assets(self) -> list[Asset]:
        return [a for a in self.registry._assets.values()]   # noqa: SLF001 (demo introspection)

    def onboard_ssh(self, **params: Any) -> ToolResult:
        """Propose an onboarding (asset.register) intent. Returns a pending
        result until approved; params are the tool's non-secret fields plus a
        ``control_plane`` target id."""
        target = params.pop("control_plane", "control-plane")
        return self.dispatcher.dispatch(Intent(
            tool="asset.register", params=params, targets=[target],
            action_class=ActionClass.ONBOARD, reason="onboard asset"))

    # -- detect / plan / remediate ---------------------------------------
    def scan(self, asset_ids: list[str]) -> list[HostFindings]:
        return self.scanner.scan_hosts(asset_ids)

    def advisories(self) -> list[Advisory]:
        return self.feed.fetch()

    def plan(self, inventory: list[HostFindings]) -> list[RemediationItem]:
        return self.planner.plan(self.advisories(), inventory)

    def remediate(self, item: RemediationItem, *, snapshot: bool | None = None,
                  existing_snapshot_ids: list[str] | None = None) -> WorkflowResult:
        return self.workflow.run(item, snapshot=snapshot,
                                 existing_snapshot_ids=existing_snapshot_ids)

    # -- approval / audit -------------------------------------------------
    def approve(self, change_set_id: str, approver: str = "operator") -> ApprovalState:
        return self.approvals.decide(change_set_id, approver, approve=True, now=self.clock())

    def audit_tail(self, n: int = 20) -> list[AuditRecord]:
        return self.audit.records()[-n:]

    def audit_ok(self) -> bool:
        return self.audit.verify()


def build_demo_engine() -> Engine:
    clock = _utcnow
    now = clock()

    registry = AssetRegistry()
    # Seed the control-plane asset: the authority under which onboarding runs.
    registry.register(Asset(
        "control-plane", "control-plane", "secops", "mgmt",
        Authorization("root-attestation", "ciso", now, now.replace(year=now.year + 1)),
    ))

    vault = Vault(DemoSecretsBackend())
    approvals = ApprovalGate()
    audit = AuditLog(clock=clock)
    policy = PolicyEngine(DEMO_POLICY)
    rate_limiter = RateLimiter.from_config(DEMO_POLICY)

    aws = DemoAwsClient()
    client_factory = lambda _creds: aws  # noqa: E731 (demo brevity)

    tools = ToolRegistry()
    tools.register(make_security_update_tool(
        SSHExecutor(SimulatedSSHTransport()),
        registry_connection_resolver(registry, clock=clock)))
    tools.register(make_ec2_discovery_tool(client_factory))
    tools.register(make_lightsail_discovery_tool(client_factory))
    tools.register(make_patch_state_tool(client_factory))
    tools.register(make_snapshot_tool(client_factory))
    tools.register(make_snapshot_delete_tool(client_factory))
    tools.register(make_patch_baseline_tool(client_factory))
    tools.register(make_asset_register_tool(registry.register))

    dispatcher = Dispatcher(
        registry=tools, policy=policy, assets=registry, approvals=approvals,
        vault=vault, audit=audit, clock=clock, rate_limiter=rate_limiter,
    )

    return Engine(
        registry=registry, dispatcher=dispatcher, approvals=approvals, audit=audit,
        scanner=AuthenticatedScanner(DemoInspector()),
        planner=RemediationPlanner(),
        workflow=RemediationWorkflow(dispatcher, credential_ref_for=lambda _a: "aws/demo"),
        feed=StaticAdvisoryFeed(DEMO_ADVISORIES),
        clock=clock,
    )


# Re-export for convenience.
__all__ = ["Engine", "build_demo_engine", "build_ssh_asset"]
