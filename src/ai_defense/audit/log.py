"""Append-only, tamper-evident audit log (hash-chained records).

Each record's hash covers the previous hash plus the canonicalized payload, so
any retroactive edit breaks the chain and ``verify()`` fails. Payloads passed in
MUST already be redacted of secrets; this module does not have the secret set.
See CLAUDE.md component 7.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

GENESIS = "GENESIS"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _canonical(payload: dict[str, Any]) -> str:
    # Stable, sorted JSON so the hash is deterministic. default=str handles
    # datetimes/enums that may appear in payloads.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class AuditRecord:
    ts: datetime
    actor: str                 # "planner" | approver id | "scanner"
    event: str                 # "intent" | "policy" | "approval" | "execute" | "result"
    payload: dict[str, Any]    # MUST be pre-redacted of secrets
    prev_hash: str
    this_hash: str

    @staticmethod
    def compute_hash(prev_hash: str, ts: datetime, actor: str, event: str,
                     payload: dict[str, Any]) -> str:
        material = "|".join([prev_hash, ts.isoformat(), actor, event, _canonical(payload)])
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditStore(Protocol):
    """Pluggable backing store for the hash chain. The in-memory default is used
    unless a durable store (e.g. ``db.repositories.SqlAuditStore``) is injected."""

    def append(self, rec: AuditRecord) -> None: ...
    def all(self) -> list[AuditRecord]: ...
    def last_hash(self) -> str: ...


class InMemoryAuditStore:
    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, rec: AuditRecord) -> None:
        self._records.append(rec)

    def all(self) -> list[AuditRecord]:
        return list(self._records)

    def last_hash(self) -> str:
        return self._records[-1].this_hash if self._records else GENESIS


class AuditLog:
    """Append-only hash chain over a pluggable store (in-memory by default)."""

    def __init__(self, clock: Callable[[], datetime] = _utcnow,
                 store: AuditStore | None = None) -> None:
        self._store: AuditStore = store or InMemoryAuditStore()
        self._clock = clock

    @property
    def last_hash(self) -> str:
        return self._store.last_hash()

    def record(self, actor: str, event: str, payload: dict[str, Any]) -> AuditRecord:
        ts = self._clock()
        prev = self._store.last_hash()
        this = AuditRecord.compute_hash(prev, ts, actor, event, payload)
        rec = AuditRecord(ts=ts, actor=actor, event=event, payload=payload,
                          prev_hash=prev, this_hash=this)
        self._store.append(rec)
        return rec

    def records(self) -> list[AuditRecord]:
        return self._store.all()

    def verify(self) -> bool:
        """Recompute the chain; any break (tamper) returns False."""
        prev = GENESIS
        for rec in self._store.all():
            expect = AuditRecord.compute_hash(prev, rec.ts, rec.actor, rec.event, rec.payload)
            if rec.prev_hash != prev or rec.this_hash != expect:
                return False
            prev = rec.this_hash
        return True
