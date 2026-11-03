"""Append-only, tamper-evident audit log (e.g. hash-chained records)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AuditRecord:
    ts: datetime
    actor: str                 # "planner" | approver id | "scanner"
    event: str                 # "intent" | "approval" | "execute" | "result"
    payload: dict[str, Any]    # MUST be pre-redacted of secrets
    prev_hash: str
    this_hash: str = ""        # computed over (prev_hash + payload)


class AuditLog:
    """TODO: hash-chain records; redact secrets on write; make storage append-only."""

    def record(self, actor: str, event: str, payload: dict) -> AuditRecord:
        raise NotImplementedError
