"""Composition root: wire the whole engine from parts.

``build_demo_engine`` assembles a fully runnable Engine with the demo backends
(no external infra). A production ``build_engine`` would differ only in the
backends it injects (real vault, paramiko transport, boto3 client, a DB-backed
audit store) — the wiring is the same.
"""

from __future__ import annotations

import os
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
    make_asset_update_tool,
    make_cloud_account_register_tool,
)
from .registry.assets import Asset, AssetRegistry, Authorization
from .report import ReportProvenance, build_report, write_report
from .report.model import Report
from .scanner.scanner import AuthenticatedScanner, HostFindings
from .ssh.catalog import (
    CATALOG,
    CONFIG_ACTIONS,
    ConfigBlockRemove,
    ConfigBlockWrite,
    DropInRemove,
    DropInWrite,
)
from .ssh.config_exec import ConfigExecutor
from .ssh.executor import SSHExecutor
from .ssh.tools import (
    make_mitigation_tool,
    make_security_update_tool,
    registry_connection_resolver,
)
from .toolset.dispatch import Dispatcher
from .toolset.intents import ActionClass, Intent, ToolResult
from .toolset.policy import PolicyEngine
from .toolset.ratelimit import RateLimiter
from .toolset.registry import ToolRegistry
from .upgrade.preflight import OsUpgradePreflight, OsUpgradeReport
from .vault.vault import Vault
from .vuln.feeds import Advisory, AdvisoryFeed, StaticAdvisoryFeed
from .vuln.mitigations import MitigationRegistry, load_mitigations
from .vuln.planner import RemediationItem, RemediationPlanner
from .vuln.workflow import RemediationWorkflow, WorkflowResult


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _mitigation_action_kind(action_name: str) -> str:
    """Classify the action a mitigation references, for read-only listing."""
    if action_name in CATALOG:
        return "command"
    action = CONFIG_ACTIONS.get(action_name)
    if isinstance(action, (DropInWrite, DropInRemove)):
        return "config-dropin"
    if isinstance(action, (ConfigBlockWrite, ConfigBlockRemove)):
        return "config-edit"
    return "unknown"


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
    preflighter: OsUpgradePreflight
    mitigations: MitigationRegistry
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

    def update_asset_connection(self, asset_id: str, *, host: str | None = None,
                                port: int | None = None, user: str | None = None,
                                key_ref: str | None = None) -> ToolResult:
        """Propose a connection-info correction (asset.update_connection) for an
        already-registered ssh-host — a rotated key_ref, a changed address/port,
        or a corrected login — preserving its authorization. Approval-gated
        (ONBOARD): returns a pending change_set_id until a human approves, then
        re-call to apply. The intent targets the asset itself, so only an already-
        authorized asset can be updated."""
        fields = {k: v for k, v in
                  {"host": host, "port": port, "user": user, "key_ref": key_ref}.items()
                  if v is not None}
        if not fields:
            return ToolResult(ok=False, tool="asset.update_connection",
                              summary="no connection fields to update "
                                      "(provide host, port, user, and/or key_ref)")
        asset = self.registry.get(asset_id)
        if asset is None or asset.connection is None:
            return ToolResult(ok=False, tool="asset.update_connection",
                              summary=f"not an updatable ssh-host asset: {asset_id}")
        return self.dispatcher.dispatch(Intent(
            tool="asset.update_connection", params={"asset_id": asset_id, **fields},
            targets=[asset_id], action_class=ActionClass.ONBOARD,
            reason=f"update connection for {asset_id}"))

    # -- detect / plan / remediate ---------------------------------------
    def scan(self, asset_ids: list[str]) -> list[HostFindings]:
        return self.scanner.scan_hosts(asset_ids)

    def advisories(self) -> list[Advisory]:
        return self.feed.fetch()

    def plan(self, inventory: list[HostFindings]) -> list[RemediationItem]:
        # for_inventory lets query-by-package feeds (OSV) fetch only what's relevant
        return self.planner.plan(self.feed.for_inventory(inventory), inventory)

    def upgrade_preflight(self, asset_ids: list[str]) -> list[OsUpgradeReport]:
        """Read-only OS-upgrade eligibility report per host: current release,
        support status, supported target/path, and any blockers. Changes
        nothing — it feeds the human decision the vuln planner escalates to."""
        today = self.clock()
        return [self.preflighter.assess(self.scanner.scan_host_for_upgrade(a), today)
                for a in asset_ids]

    # -- reporting / export ----------------------------------------------
    def build_report(self, asset_ids: list[str], *,
                     include_preflight: bool = True) -> Report:
        """Scan + plan (+ preflight), correlated into one read-only report model.

        One authenticated scan per host feeds both the vuln plan and the upgrade
        preflight, so a report is a single consistent snapshot.

        Scan-exempt hosts (deliberately not SSH-reachable) are not scanned at all;
        they appear in the report marked *exempt* rather than as a scan failure."""
        exempt = self._scan_exempt(asset_ids)
        to_scan = [a for a in asset_ids if a not in exempt]
        inv = [self.scanner.scan_host_for_upgrade(a) for a in to_scan]
        plan = self.planner.plan(self.feed.for_inventory(inv), inv)
        today = self.clock()
        preflights = ([self.preflighter.assess(f, today) for f in inv]
                      if include_preflight else [])
        return build_report(inv, plan, preflights, self._report_provenance(asset_ids),
                            audit_verified=self.audit_ok(),
                            connections=self._connections(asset_ids),
                            exempt=exempt)

    def _scan_exempt(self, asset_ids: list[str]) -> dict[str, str]:
        """Asset ids (from the requested set) flagged scan-exempt in the trusted
        registry, mapped to the operator's reason. A scan-exempt ssh-host is one
        intentionally not SSH-reachable, so a scan failure on it is expected, not
        a fault."""
        wanted = set(asset_ids)
        out: dict[str, str] = {}
        for a in self.registry.all():
            attrs = getattr(a, "attributes", None) or {}
            if a.asset_id in wanted and attrs.get("scan_exempt"):
                out[a.asset_id] = (attrs.get("scan_exempt_reason")
                                   or "SSH not available (configured scan-exempt)")
        return out

    def _connections(self, asset_ids: list[str]) -> dict[str, dict]:
        """Address (host/port) per asset, resolved from the trusted registry so
        the report shows the real IP, not planner-supplied text."""
        wanted = set(asset_ids)
        out: dict[str, dict] = {}
        for a in self.registry.all():
            conn = getattr(a, "connection", None)
            if conn is not None and a.asset_id in wanted:
                out[a.asset_id] = {"host": conn.host, "port": conn.port}
        return out

    def report(self, asset_ids: list[str], *, out_dir: str | None = None,
               include_preflight: bool = True) -> tuple[Report, dict[str, str]]:
        """Build the report and write all four deliverables to local files.

        With ``out_dir`` the files are written there; otherwise a timestamped
        directory under ``./reports``. Returns the report model and the written
        file paths. Local-only — a fleet vulnerability inventory never leaves the
        operator's infrastructure."""
        report = self.build_report(asset_ids, include_preflight=include_preflight)
        if out_dir is None:
            stamp = report.provenance.generated_at.strftime("%Y%m%dT%H%M%SZ")
            out_dir = os.path.join(os.getcwd(), "reports", stamp)
        return report, write_report(report, out_dir)

    def _report_provenance(self, scope: list[str]) -> ReportProvenance:
        from .scanner.ssh_inspector import SSHHostInspector
        from .vuln.kev import KevEnrichedFeed
        from .vuln.osv import OsvFeed

        feed = self.feed
        kev = isinstance(feed, KevEnrichedFeed)
        inner = getattr(feed, "_inner", feed)
        source = "osv.dev" if isinstance(inner, OsvFeed) else type(inner).__name__
        scan_mode = ("authenticated"
                     if isinstance(self.scanner.inspector, SSHHostInspector)
                     else "simulated")
        # for_inventory was just run during build_report, so the feed's health
        # reflects this report. A degraded advisory fetch (OSV down/rate-limited)
        # must be flagged — otherwise a report missing findings reads as clean.
        health = getattr(inner, "health", None)
        degraded = bool(health is not None and health.degraded)
        note = health.summary() if degraded else None
        return ReportProvenance(generated_at=self.clock(), scope=list(scope),
                                advisory_source=source, kev_enabled=kev,
                                scan_mode=scan_mode,
                                feed_degraded=degraded, feed_note=note)

    def advisory_feed_health(self) -> tuple[bool, str | None]:
        """Whether the most recent advisory fetch (``feed.for_inventory``) was
        incomplete, plus a human-readable note. Lets a caller distinguish "no
        patch exists" from "the advisory feed was degraded this run" (fail-safe,
        hard rule #7) — so a throttled OSV query never reads as a clean negative."""
        inner = getattr(self.feed, "_inner", self.feed)
        health = getattr(inner, "health", None)
        if health is not None and health.degraded:
            return True, health.summary()
        return False, None

    def remediate(self, item: RemediationItem, *, snapshot: bool | None = None,
                  existing_snapshot_ids: list[str] | None = None) -> WorkflowResult:
        return self.workflow.run(item, snapshot=snapshot,
                                 existing_snapshot_ids=existing_snapshot_ids)

    def list_mitigations(self) -> list[dict]:
        """Read-only: the mitigations currently loaded (built-ins + any folder),
        each with the CVE(s)/key it covers, the action it runs, that action's kind
        (command / config-dropin / config-edit), and the advisory it cites — so
        'what mitigations are enabled?' is answerable without inspecting config."""
        return sorted(
            ({
                "mitigation_id": m.mitigation_id,
                "cves": list(m.cves),
                "title": m.title,
                "source_ref": m.source_ref,
                "action": m.template,
                "kind": _mitigation_action_kind(m.template),
            } for m in self.mitigations.by_id.values()),
            key=lambda d: d["mitigation_id"])

    def mitigate(self, asset_id: str, cve_id: str) -> ToolResult:
        """Propose the published mitigation for a CVE where the vendor patch can't
        be installed (e.g. an EOL OS without ESM). Approval-gated (MITIGATE_CANARY)
        and reversible. Only mitigations in the loaded registry (built-ins + the
        mitigations folder) are offered — an uncatalogued CVE escalates to a
        human, never an invented fix (rule #6). Returns a pending change_set_id
        until approved; re-call to apply."""
        return self._mitigation_dispatch(asset_id, cve_id, reverse=False)

    def revert_mitigation(self, asset_id: str, cve_id: str) -> ToolResult:
        """Undo a previously applied mitigation by running its recorded rollback
        action (restore the setuid bit, remove the sysctl/nginx drop-in, delete the
        managed sshd block, …). Same enforcement as applying it — MUTATING,
        approval-gated (MITIGATE_CANARY), audited — because reversing a hardening
        step is itself a state-changing remote action. Returns a pending
        change_set_id until approved; re-call to apply."""
        return self._mitigation_dispatch(asset_id, cve_id, reverse=True)

    def _mitigation_dispatch(self, asset_id: str, cve_id: str, *, reverse: bool) -> ToolResult:
        m = self.mitigations.for_cve(cve_id)
        if m is None:
            return ToolResult(
                ok=False, tool="mitigation.apply_hardening",
                summary=f"no catalogued mitigation for {cve_id} — escalate for a human "
                        f"decision (an OS upgrade may be the real fix)")
        verb = "revert" if reverse else "mitigate"
        params = {"asset_id": asset_id, "mitigation_id": m.mitigation_id}
        if reverse:
            params["reverse"] = True
        return self.dispatcher.dispatch(Intent(
            tool="mitigation.apply_hardening",
            params=params,
            targets=[asset_id], action_class=ActionClass.MITIGATE_CANARY,
            reason=f"{verb} {cve_id} on {asset_id}: {m.title}", source_ref=m.source_ref))

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
    mitigations_dir: str | None = None,
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

    # Mitigation catalogue: built-ins + any operator folder, each entry's action
    # validated against the reviewed allowlist (catalog commands + config actions);
    # a file can reference one but can't define a new one.
    _allowed = set(CATALOG) | set(CONFIG_ACTIONS)
    mitigations = load_mitigations(mitigations_dir, allowed_templates=_allowed)

    tools = ToolRegistry()
    ssh_executor = SSHExecutor(the_transport)
    tools.register(make_security_update_tool(ssh_executor, conn_resolver))
    tools.register(make_mitigation_tool(ssh_executor, conn_resolver,
                                        mitigations=mitigations.by_id,
                                        config_executor=ConfigExecutor(ssh_executor),
                                        config_actions=CONFIG_ACTIONS))
    tools.register(make_ec2_discovery_tool(client_factory))
    tools.register(make_lightsail_discovery_tool(client_factory))
    tools.register(make_patch_state_tool(client_factory))
    tools.register(make_snapshot_tool(client_factory))
    tools.register(make_snapshot_delete_tool(client_factory))
    tools.register(make_patch_baseline_tool(client_factory))
    tools.register(make_regions_tool(client_factory))
    tools.register(make_asset_register_tool(registry.register))   # writes through to DB
    tools.register(make_asset_update_tool(registry.update_connection))
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
        preflighter=OsUpgradePreflight(),
        mitigations=mitigations,
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
    mitigations_dir: str | None = None,
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
        mitigations_dir=mitigations_dir,
    )


def build_demo_engine(session_factory=None, *, aws_region: str | None = None,
                      advisory_feed: Any = None, enrich_kev: bool = False,
                      mitigations_dir: str | None = None) -> Engine:
    """Back-compat wrapper: the demo engine with simulated backends (persistent
    when a session_factory is given; live boto3 when aws_region is set)."""
    return build_engine(session_factory=session_factory, aws_region=aws_region,
                        advisory_feed=advisory_feed, enrich_kev=enrich_kev,
                        mitigations_dir=mitigations_dir)


# Re-export for convenience.
__all__ = ["Engine", "build_engine", "build_ssh_engine", "build_demo_engine",
           "build_ssh_asset"]
