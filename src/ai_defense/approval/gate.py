"""Human approval gate (CLAUDE.md approval model).

Per change-set approval: N-of-M approvers, expiry if not acted on, and rejection.
Canary->fleet gating (fleet unlocked only after canary health checks pass) is
represented by ``unlock_after`` and confirmed via ``mark_precondition_met``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass
class ApprovalRequest:
    change_set_id: str
    resolved_commands: list[str]      # exact commands/ops shown to the approver
    blast_radius: int
    source_ref: str | None
    requested_at: datetime
    expires_at: datetime
    approvals_required: int = 1
    unlock_after: str | None = None   # e.g. "canary_health_ok"; None = no precondition
    state: ApprovalState = ApprovalState.PENDING
    approvers: list[str] = field(default_factory=list)
    precondition_met: bool = False


class ApprovalGate:
    def __init__(self) -> None:
        self._reqs: dict[str, ApprovalRequest] = {}

    def request(self, req: ApprovalRequest) -> str:
        # Idempotent: a repeated request for the same change-set returns the existing one.
        self._reqs.setdefault(req.change_set_id, req)
        return req.change_set_id

    def get(self, change_set_id: str) -> ApprovalRequest | None:
        return self._reqs.get(change_set_id)

    def mark_precondition_met(self, change_set_id: str) -> None:
        req = self._reqs.get(change_set_id)
        if req is not None:
            req.precondition_met = True

    def decide(self, change_set_id: str, approver: str, approve: bool,
               now: datetime | None = None) -> ApprovalState:
        now = now or _utcnow()
        req = self._reqs.get(change_set_id)
        if req is None:
            raise KeyError(f"no approval request: {change_set_id}")
        self._refresh_expiry(req, now)
        if req.state in (ApprovalState.REJECTED, ApprovalState.EXPIRED, ApprovalState.APPROVED):
            return req.state
        if not approve:
            req.state = ApprovalState.REJECTED
            return req.state
        if approver not in req.approvers:
            req.approvers.append(approver)   # N-of-M: distinct approvers only
        if len(req.approvers) >= req.approvals_required:
            req.state = ApprovalState.APPROVED
        return req.state

    def state_for(self, change_set_id: str, now: datetime | None = None) -> ApprovalState:
        now = now or _utcnow()
        req = self._reqs.get(change_set_id)
        if req is None:
            return ApprovalState.PENDING
        self._refresh_expiry(req, now)
        return req.state

    def is_cleared(self, change_set_id: str, now: datetime | None = None) -> bool:
        """Approved AND any canary->fleet precondition satisfied."""
        req = self._reqs.get(change_set_id)
        if req is None:
            return False
        if self.state_for(change_set_id, now) != ApprovalState.APPROVED:
            return False
        if req.unlock_after is not None and not req.precondition_met:
            return False
        return True

    @staticmethod
    def _refresh_expiry(req: ApprovalRequest, now: datetime) -> None:
        if req.state == ApprovalState.PENDING and now >= req.expires_at:
            req.state = ApprovalState.EXPIRED
