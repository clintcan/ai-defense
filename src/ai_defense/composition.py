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
from .approval.gate import ApprovalGate, ApprovalState, PersistentApprovalGate
from .audit.log import AuditLog, AuditRecord
from .cloud.tools import (
    EC2_DISCOVERY_TOOL,
    LIGHTSAIL_DISCOVERY_TOOL,
    PATCH_BASELINE_TOOL,
    PATCH_STATE_TOOL,
    REGIONS_TOOL,
    make_ec2_discovery_tool,
    make_lightsail_discovery_tool,
    make_patch_baseline_tool,
    make_patch_state_tool,
    make_regions_tool,
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
from .onboarding import (
    build_ssh_asset,
    make_asset_register_tool,
    make_cloud_account_register_tool,
)
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
from .vuln.feeds import Advisory, AdvisoryFeed, StaticAdvisoryFeed
from .vuln.planner import RemediationItem, RemediationPlanner
from .vuln.workflow import RemediationWorkflow, WorkflowResult


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class Engine:
    """The wired system. High-level methods are thin wrappers over the toolset,
    so every call still passes through policy, authorization, approval, rate
    limits, redaction, and the audit log."""

    registry: Any           # AssetRegistry or db.PersistentAssetRegistry (duck-typed)
    dispatcher: Dispatcher
    approvals: ApprovalGate
    audit: AuditLog
    scanner: AuthenticatedScanner
    planner: RemediationPlanner
    workflow: RemediationWorkflow
    feed: AdvisoryFeed
    clock: Callable[[], datetime] = _utcnow

    # -- inventory --------------------------------------------------------
    def list_assets(self) -> list[Asset]:
        return self.registry.all()

    def onboard_ssh(self, **params: Any) -> ToolResult:
        """Propose an onboarding (asset.register) intent. Returns a pending
        result until approved; params are the tool's non-secret fields plus a
        ``control_plane`` target id."""
        target = params.pop("control_plane", "control-plane")
        return self.dispatcher.dispatch(Intent(
            tool="asset.register", params=params, targets=[target],
            action_class=ActionClass.ONBOARD, reason="onboard asset"))

    def onboard_cloud_account(self, **params: Any) -> ToolResult:
        """Propose a cloud-account onboarding (cloud.register_account) intent."""
        target = params.pop("control_plane", "control-plane")
        return self.dispatcher.dispatch(Intent(
            tool="cloud.register_account", params=params, targets=[target],
            action_class=ActionClass.ONBOARD, reason="onboard cloud account"))

    # -- detect / plan / remediate ---------------------------------------
    def scan(self, asset_ids: list[str]) -> list[HostFindings]:
        return self.scanner.scan_hosts(asset_ids)

    def advisories(self) -> list[Advisory]:
        return self.feed.fetch()

    def plan(self, inventory: list[HostFindings]) -> list[RemediationItem]:
        # for_inventory lets query-by-package feeds (OSV) fetch only what's relevant
        return self.planner.plan(self.feed.for_inventory(inventory), inventory)

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

    # -- cloud (AWS) ------------------------------------------------------
    def _account_credential_ref(self, account_id: str) -> str:
        asset = self.registry.get(account_id)
        if asset is None:
            raise KeyError(f"cloud account not registered: {account_id}")
        ref = (asset.attributes or {}).get("credential_ref")
        if not ref:
            raise KeyError(f"account {account_id} has no credential_ref")
        return ref

    def _cloud_dispatch(self, tool: str, account_id: str, action_class: ActionClass,
                        extra: dict, reason: str) -> ToolResult:
        params = {"account": account_id,
                  "credential_ref": self._account_credential_ref(account_id), **extra}
        return self.dispatcher.dispatch(Intent(
            tool=tool, params=params, targets=[account_id],
            action_class=action_class, reason=reason))

    def cloud_regions(self, account_id: str) -> ToolResult:
        """Regions available to a registered cloud account (read-only)."""
        return self._cloud_dispatch(REGIONS_TOOL, account_id, ActionClass.DISCOVERY,
                                    {}, "list cloud regions")

    def cloud_discover(self, account_id: str) -> ToolResult:
        """EC2 + Lightsail inventory for a registered account (read-only)."""
        ec2 = self._cloud_dispatch(EC2_DISCOVERY_TOOL, account_id,
                                   ActionClass.DISCOVERY, {}, "cloud inventory (ec2)")
        ls = self._cloud_dispatch(LIGHTSAIL_DISCOVERY_TOOL, account_id,
                                  ActionClass.DISCOVERY, {}, "cloud inventory (lightsail)")
        return ec2, ls

    def cloud_patch_state(self, account_id: str, instance_ids: list[str]) -> ToolResult:
        return self._cloud_dispatch(PATCH_STATE_TOOL, account_id, ActionClass.SCAN,
                                    {"instance_ids": list(instance_ids)},
                                    "cloud patch compliance")

    def cloud_remediate(self, account_id: str, instance_ids: list[str],
                        baseline: str | None = None,
                        action_class: ActionClass = ActionClass.PATCH_CANARY) -> ToolResult:
        extra: dict = {"instance_ids": list(instance_ids)}
        if baseline:
            extra["baseline"] = baseline
        return self._cloud_dispatch(PATCH_BASELINE_TOOL, account_id, action_class,
                                    extra, "apply SSM patch baseline")


_CONTROL_PLANE_ID = "control-plane"


def _control_plane_asset(now: datetime) -> Asset:
    return Asset(
        _CONTROL_PLANE_ID, "control-plane", "secops", "mgmt",
        Authorization("root-attestation", "ciso", now, now.replace(year=now.year + 1)),
    )


def build_engine(
    *,
    session_factory=None,
    policy_config: dict | None = None,
    aws_client: Any = None,
    aws_client_factory: Any = None,
    aws_region: str | None = None,
    inspector: Any = None,
    inspector_factory: Any = None,
    transport: Any = None,
    secrets_backend: Any = None,
    advisories: list[Advisory] | None = None,
    advisory_feed: Any = None,
    enrich_kev: bool = False,
    kev_catalog: Any = None,
) -> Engine:
    """Wire an Engine from parts.

    With ``session_factory`` (from ``db.init_db``) the asset registry, approvals,
    and audit log are **persistent and cross-process** — onboarded assets and
    approvals survive restarts and are shared with the operator CLI. Without it,
    all three are in-memory (single process).

    The backend arguments default to the simulated demo backends; a production
    build injects real ones (paramiko transport, boto3 client, a real vault) —
    the wiring is otherwise identical.
    """
    clock = _utcnow
    now = clock()
    policy_config = policy_config if policy_config is not None else DEMO_POLICY

    vault = Vault(secrets_backend or DemoSecretsBackend())

    if session_factory is not None:
        from .db.repositories import (
            ApprovalRepository,
            AssetRepository,
            PersistentAssetRegistry,
            SqlAuditStore,
        )
        asset_repo = AssetRepository(session_factory)
        if asset_repo.get(_CONTROL_PLANE_ID) is None:   # seed once, durably
            asset_repo.save(_control_plane_asset(now))
        registry: Any = PersistentAssetRegistry(asset_repo)
        approvals: Any = PersistentApprovalGate(ApprovalRepository(session_factory))
        audit = AuditLog(clock=clock, store=SqlAuditStore(session_factory))
    else:
        registry = AssetRegistry()
        registry.register(_control_plane_asset(now))
        approvals = ApprovalGate()
        audit = AuditLog(clock=clock)

    policy = PolicyEngine(policy_config)
    rate_limiter = RateLimiter.from_config(policy_config)

    if aws_client_factory is not None:
        client_factory = aws_client_factory
    elif aws_region is not None:                      # live boto3 (profile/role/keys)
        from .cloud.aws_client import boto3_client_factory
        client_factory = boto3_client_factory(aws_region)
    else:                                             # simulated
        aws = aws_client or DemoAwsClient()
        client_factory = lambda _creds: aws  # noqa: E731 (brevity)

    the_transport = transport or SimulatedSSHTransport()
    conn_resolver = registry_connection_resolver(registry, clock=clock)

    tools = ToolRegistry()
    tools.register(make_security_update_tool(
        SSHExecutor(the_transport), conn_resolver))
    tools.register(make_ec2_discovery_tool(client_factory))
    tools.register(make_lightsail_discovery_tool(client_factory))
    tools.register(make_patch_state_tool(client_factory))
    tools.register(make_snapshot_tool(client_factory))
    tools.register(make_snapshot_delete_tool(client_factory))
    tools.register(make_patch_baseline_tool(client_factory))
    tools.register(make_regions_tool(client_factory))
    tools.register(make_asset_register_tool(registry.register))   # writes through to DB
    tools.register(make_cloud_account_register_tool(registry.register))

    dispatcher = Dispatcher(
        registry=tools, policy=policy, assets=registry, approvals=approvals,
        vault=vault, audit=audit, clock=clock, rate_limiter=rate_limiter,
    )

    if inspector_factory is not None:
        host_inspector = inspector_factory(conn_resolver, vault, the_transport)
    else:
        host_inspector = inspector or DemoInspector()

    feed = advisory_feed or StaticAdvisoryFeed(
        advisories if advisories is not None else DEMO_ADVISORIES)
    if enrich_kev:
        from .vuln.kev import KevCatalog, KevEnrichedFeed
        feed = KevEnrichedFeed(feed, kev_catalog or KevCatalog())

    return Engine(
        registry=registry, dispatcher=dispatcher, approvals=approvals, audit=audit,
        scanner=AuthenticatedScanner(host_inspector),
        planner=RemediationPlanner(),
        workflow=RemediationWorkflow(dispatcher, credential_ref_for=lambda _a: "aws/demo"),
        feed=feed,
        clock=clock,
    )


def build_ssh_engine(
    *,
    key_dir: str,
    session_factory=None,
    known_hosts: str | None = None,
    allow_unknown_hosts: bool = False,
    policy_config: dict | None = None,
    advisories: list[Advisory] | None = None,
    advisory_feed: Any = None,
    enrich_kev: bool = False,
    aws_region: str | None = None,
) -> Engine:
    """Engine with the REAL SSH backend: a paramiko transport, a file-backed
    vault (keys under ``key_dir``, referenced by key_ref), and a read-only SSH
    host inspector. Cloud tools remain simulated (the AWS backend is separate).

    Requires the ``ssh`` extra (paramiko). Host-key verification is on unless
    ``allow_unknown_hosts`` is set.
    """
    from .scanner.ssh_inspector import SSHHostInspector
    from .ssh.paramiko_transport import ParamikoTransport
    from .vault.backends import FileVaultBackend

    transport = ParamikoTransport(known_hosts=known_hosts,
                                  allow_unknown_hosts=allow_unknown_hosts)

    def inspector_factory(conn_resolver, vault, tport):
        return SSHHostInspector(conn_resolver, vault, tport)

    return build_engine(
        session_factory=session_factory,
        policy_config=policy_config,
        transport=transport,
        secrets_backend=FileVaultBackend(key_dir),
        inspector_factory=inspector_factory,
        advisories=advisories,
        advisory_feed=advisory_feed,
        enrich_kev=enrich_kev,
        aws_region=aws_region,
    )


def build_demo_engine(session_factory=None, *, aws_region: str | None = None,
                      advisory_feed: Any = None, enrich_kev: bool = False) -> Engine:
    """Back-compat wrapper: the demo engine with simulated backends (persistent
    when a session_factory is given; live boto3 when aws_region is set)."""
    return build_engine(session_factory=session_factory, aws_region=aws_region,
                        advisory_feed=advisory_feed, enrich_kev=enrich_kev)


# Re-export for convenience.
__all__ = ["Engine", "build_engine", "build_ssh_engine", "build_demo_engine",
           "build_ssh_asset"]
