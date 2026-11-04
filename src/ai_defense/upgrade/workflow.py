"""The strongly-gated OS_UPGRADE workflow (CLAUDE.md 6c).

Drives an **in-place** Ubuntu release upgrade on one host, with every safety rail
the preflight only *advises* today:

    preflight gate (must be READY)
      -> mandatory snapshot (PROTECTIVE, autonomous) -- no snapshot => abort
      -> gated upgrade+reboot (os_upgrade_canary / _fleet, human-approved)
      -> reconnect poll -> health check (OS == target?) -> post-upgrade re-scan
      -> on failure: HALT, keep the snapshot as the restore point, escalate

Why no automatic rollback: a dist-upgrade cannot be reliably undone in place, so
the mandatory pre-upgrade snapshot *is* the rollback. If the host does not come
back healthy, the workflow halts and surfaces the retained snapshot for a human
to restore (operator choice, 2026-11-05) rather than attempting an unattended
instance rebuild.

The reconnect/health/re-scan steps are read-only (they go through the scanner, so
secrets stay inside the toolset). Only the upgrade+reboot is mutating, and it is
one approval-gated change (``os.release_upgrade``).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..cloud.tools import SNAPSHOT_TOOL
from ..scanner.scanner import AuthenticatedScanner, HostFindings
from ..ssh.tools import OS_UPGRADE_TOOL
from ..toolset.dispatch import Dispatcher
from ..toolset.intents import ActionClass, Intent, ToolResult
from .preflight import OsUpgradePreflight, OsUpgradeReport, UpgradeVerdict

# Workflow statuses.
PREFLIGHT_BLOCKED = "preflight_blocked"     # not READY (eol-but-blocked / current / unknown)
SNAPSHOT_FAILED = "snapshot_failed"
UPGRADE_PENDING = "upgrade_pending"         # awaiting human approval
UPGRADE_BLOCKED = "upgrade_blocked"         # policy refusal, or the upgrade command failed
HEALTH_FAILED_HALTED = "health_failed_halted"  # didn't come back healthy -> halt + restore point
UPGRADED = "upgraded"                       # reconnected, on target release, re-scanned


@dataclass
class OsUpgradeResult:
    asset_id: str
    status: str
    preflight: OsUpgradeReport | None = None
    snapshot: ToolResult | None = None
    upgrade: ToolResult | None = None
    snapshot_ids: list[str] = field(default_factory=list)
    change_set_id: str | None = None
    reconnected: bool = False
    post_os: str | None = None              # VERSION_ID observed after the upgrade
    post_scan: HostFindings | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def snapshotted(self) -> bool:
        return bool(self.snapshot_ids)


class OsUpgradeWorkflow:
    def __init__(
        self,
        dispatcher: Dispatcher,
        scanner: AuthenticatedScanner,
        preflighter: OsUpgradePreflight,
        *,
        credential_ref_for: Callable[[str], str],
        service_for: Callable[[str], str] = lambda _a: "ec2",
        reconnect_attempts: int = 30,
        reconnect_delay_s: float = 10.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._dispatcher = dispatcher
        self._scanner = scanner
        self._preflighter = preflighter
        self._cred_for = credential_ref_for
        self._service_for = service_for
        self._attempts = max(1, reconnect_attempts)
        self._delay = reconnect_delay_s
        self._sleep = sleep

    def run(
        self,
        asset_id: str,
        *,
        canary: bool = True,
        existing_snapshot_ids: list[str] | None = None,
    ) -> OsUpgradeResult:
        # 1. Preflight gate (read-only). Only a READY host proceeds.
        report = self._preflighter.assess(self._scanner.scan_host_for_upgrade(asset_id))
        if report.verdict is not UpgradeVerdict.READY:
            return OsUpgradeResult(
                asset_id, PREFLIGHT_BLOCKED, preflight=report,
                notes=[f"preflight verdict is {report.verdict.value}, not ready; "
                       "not upgrading"] + list(report.notes))
        target = report.target_version

        # 2. Mandatory snapshot first (autonomous, PROTECTIVE). The upgrade never
        #    proceeds without a restore point; the only way to skip re-snapshotting
        #    is to pass the ids from a prior run (existing_snapshot_ids).
        snap_ids = list(existing_snapshot_ids or [])
        snap_result: ToolResult | None = None
        if not snap_ids:
            snap_result = self._dispatcher.dispatch(self._snapshot_intent(asset_id))
            if not snap_result.ok:
                return OsUpgradeResult(asset_id, SNAPSHOT_FAILED, preflight=report,
                                       snapshot=snap_result)
            snap_ids = list(snap_result.data.get("snapshot_ids", []))
        if not snap_ids:
            return OsUpgradeResult(
                asset_id, SNAPSHOT_FAILED, preflight=report, snapshot=snap_result,
                notes=["no snapshot id available; refusing to upgrade without a restore point"])

        # 3. The approval-gated upgrade + reboot.
        ac = ActionClass.OS_UPGRADE_CANARY if canary else ActionClass.OS_UPGRADE_FLEET
        intent = Intent(
            tool=OS_UPGRADE_TOOL,
            params={"asset_id": asset_id, "target_version": target,
                    "snapshot_id": snap_ids[0] if snap_ids else None},
            targets=[asset_id], action_class=ac,
            reason=f"in-place OS upgrade of {asset_id} to {target}",
            source_ref=report.source_ref)
        up = self._dispatcher.dispatch(intent)
        if not up.ok:
            # "pending" = awaiting approval; "approved" = approved but the
            # canary->fleet precondition is not yet met. Both are still waiting.
            if up.data.get("approval_state") in ("pending", "approved"):
                return OsUpgradeResult(asset_id, UPGRADE_PENDING, preflight=report,
                                       snapshot=snap_result, upgrade=up, snapshot_ids=snap_ids,
                                       change_set_id=up.data.get("change_set_id"))
            return OsUpgradeResult(asset_id, UPGRADE_BLOCKED, preflight=report,
                                   snapshot=snap_result, upgrade=up, snapshot_ids=snap_ids)

        # 4. Upgrade applied + reboot issued -> confirm the host comes back healthy.
        reconnected, post = self._await_reconnect(asset_id)
        restore = (f"HALTED — restore retained snapshot(s) {snap_ids or '<none>'} on {asset_id}; "
                   "an in-place upgrade cannot be reverted automatically")
        if not reconnected:
            return OsUpgradeResult(
                asset_id, HEALTH_FAILED_HALTED, preflight=report, snapshot=snap_result,
                upgrade=up, snapshot_ids=snap_ids, reconnected=False, post_scan=post,
                notes=[f"host did not reconnect within {self._attempts} checks. {restore}"])
        post_version = (post.os_release or {}).get("VERSION_ID") if post else None
        if target and post_version != target:
            return OsUpgradeResult(
                asset_id, HEALTH_FAILED_HALTED, preflight=report, snapshot=snap_result,
                upgrade=up, snapshot_ids=snap_ids, reconnected=True,
                post_os=post_version, post_scan=post,
                notes=[f"reconnected but OS is {post_version}, expected {target}. {restore}"])

        # 5. Healthy on the target release; `post` is the post-upgrade re-scan.
        return OsUpgradeResult(
            asset_id, UPGRADED, preflight=report, snapshot=snap_result, upgrade=up,
            snapshot_ids=snap_ids, reconnected=True, post_os=post_version, post_scan=post,
            notes=[f"upgraded to {post_version}; snapshot(s) {snap_ids} retained until the fix "
                   "is confirmed stable (delete via the CLEANUP action)."])

    def _await_reconnect(self, asset_id: str) -> tuple[bool, HostFindings | None]:
        """Poll the (read-only) scanner until the host answers and reports its
        release, or we run out of attempts. A successful scan populates
        ``os_release``; a failed one (still rebooting / unreachable) leaves it empty."""
        last: HostFindings | None = None
        for i in range(self._attempts):
            f = self._scanner.scan_host(asset_id)
            if f.os_release:
                return True, f
            last = f
            if i < self._attempts - 1:
                self._sleep(self._delay)
        return False, last

    def _snapshot_intent(self, asset_id: str) -> Intent:
        return Intent(
            tool=SNAPSHOT_TOOL,
            params={"instance_id": asset_id, "service": self._service_for(asset_id),
                    "credential_ref": self._cred_for(asset_id),
                    "reason": f"pre-OS-upgrade snapshot of {asset_id}"},
            targets=[asset_id], action_class=ActionClass.PROTECTIVE,
            reason=f"mandatory pre-OS-upgrade snapshot for {asset_id}")
