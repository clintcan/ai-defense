"""Approval workflow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class ApprovalState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    change_set_id: str
    resolved_commands: list[str]      # exact commands/ops shown to the approver
    blast_radius: int
    source_ref: str | None
    requested_at: datetime
    expires_at: datetime
    state: ApprovalState = ApprovalState.PENDING
    approvals_required: int = 1
    approvals: list[str] = None        # type: ignore[assignment]


class ApprovalGate:
    """TODO: persist requests, enforce N-of-M approvals, expiry, and canary
    gating (fleet approval unlocked only after canary health checks pass)."""

    def request(self, req: ApprovalRequest) -> str:
        raise NotImplementedError

    def decide(self, change_set_id: str, approver: str, approve: bool) -> ApprovalState:
        raise NotImplementedError
