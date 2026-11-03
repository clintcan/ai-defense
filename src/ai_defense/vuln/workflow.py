"""Remediation workflow: sequence an optional protective snapshot before the
approval-gated patch, and offer explicit snapshot cleanup once a fix is stable.

Ordering and safety rules:
  * The snapshot (PROTECTIVE, autonomous) runs BEFORE the patch so a rollback
    point exists first.
  * If a snapshot was requested but fails, the patch is NOT attempted — never
    change a host without a backup.
  * The snapshot is taken once: after approval, re-run with the returned
    ``existing_snapshot_ids`` to skip re-snapshotting.
  * The snapshot is retained through approval and through a failed patch (that is
    when you most need it). Deleting it is a separate, deliberate, approval-gated
    CLEANUP action the caller invokes only once the fix is confirmed stable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..cloud.tools import SNAPSHOT_DELETE_TOOL, SNAPSHOT_TOOL
from ..toolset.dispatch import Dispatcher
from ..toolset.intents import ActionClass, Intent, ToolResult
from .planner import RemediationItem, RemediationKind

# Workflow statuses.
NOT_A_PATCH = "not_a_patch"
SNAPSHOT_FAILED = "snapshot_failed"
PATCHED = "patched"
PATCH_PENDING = "patch_pending"
PATCH_BLOCKED = "patch_blocked"


@dataclass
class WorkflowResult:
    item: RemediationItem
    status: str
    snapshot: ToolResult | None = None
    patch: ToolResult | None = None
    snapshot_ids: list[str] = field(default_factory=list)

    @property
    def snapshotted(self) -> bool:
        return bool(self.snapshot_ids)


class RemediationWorkflow:
    def __init__(
        self,
        dispatcher: Dispatcher,
        *,
        credential_ref_for: Callable[[str], str],
        service_for: Callable[[str], str] = lambda _a: "ec2",
        snapshot_by_default: bool = True,
    ) -> None:
        self._dispatcher = dispatcher
        self._cred_for = credential_ref_for
        self._service_for = service_for
        self._snapshot_default = snapshot_by_default

    def run(
        self,
        item: RemediationItem,
        *,
        snapshot: bool | None = None,
        existing_snapshot_ids: list[str] | None = None,
    ) -> WorkflowResult:
        if item.kind is not RemediationKind.PATCH or item.intent is None:
            return WorkflowResult(item, status=NOT_A_PATCH)

        do_snapshot = self._snapshot_default if snapshot is None else snapshot
        snap_ids = list(existing_snapshot_ids or [])
        snap_result: ToolResult | None = None

        # 1. Snapshot first (unless disabled or already done), abort on failure.
        if do_snapshot and not snap_ids:
            snap_result = self._dispatcher.dispatch(self._snapshot_intent(item))
            if not snap_result.ok:
                return WorkflowResult(item, status=SNAPSHOT_FAILED, snapshot=snap_result)
            snap_ids = list(snap_result.data.get("snapshot_ids", []))

        # 2. The approval-gated patch.
        patch_result = self._dispatcher.dispatch(item.intent)
        if patch_result.ok:
            status = PATCHED
        elif patch_result.data.get("approval_state") == "pending":
            status = PATCH_PENDING
        else:
            status = PATCH_BLOCKED
        return WorkflowResult(item, status=status, snapshot=snap_result,
                              patch=patch_result, snapshot_ids=snap_ids)

    def delete_snapshot(
        self, asset_id: str, snapshot_ids: list[str], *, service: str | None = None,
    ) -> ToolResult:
        """Delete the retained snapshot(s) once the fix is stable. Dispatched as
        CLEANUP, so it passes through the approval gate like any destructive op."""
        intent = Intent(
            tool=SNAPSHOT_DELETE_TOOL,
            params={
                "instance_id": asset_id,
                "snapshot_ids": list(snapshot_ids),
                "service": service or self._service_for(asset_id),
                "credential_ref": self._cred_for(asset_id),
            },
            targets=[asset_id],
            action_class=ActionClass.CLEANUP,
            reason=f"delete pre-change snapshot(s) for {asset_id} after stable fix",
        )
        return self._dispatcher.dispatch(intent)

    def _snapshot_intent(self, item: RemediationItem) -> Intent:
        asset = item.asset_id
        return Intent(
            tool=SNAPSHOT_TOOL,
            params={
                "instance_id": asset,
                "service": self._service_for(asset),
                "credential_ref": self._cred_for(asset),
                "reason": item.source_ref,
            },
            targets=[asset],
            action_class=ActionClass.PROTECTIVE,
            reason=f"pre-change snapshot for {item.source_ref}",
            source_ref=item.source_ref,
        )
