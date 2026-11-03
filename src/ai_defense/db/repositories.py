"""Repositories translating between domain dataclasses and DB rows.

Each repository takes a session factory and opens a short-lived session per
operation. Domain objects (Asset, Authorization, ApprovalRequest, HostFindings,
AuditRecord) remain the in-memory contract; nothing here changes their shape.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from ..approval.gate import ApprovalGate, ApprovalRequest, ApprovalState
from ..audit.log import GENESIS, AuditRecord
from ..registry.assets import (
    Asset,
    AssetRegistry,
    Authorization,
    ConnectionInfo,
    _require_authorized,
)
from ..scanner.scanner import HostFindings
from .models import (
    ApprovalRow,
    ApprovalVoteRow,
    AssetRow,
    AuditRow,
    AuthorizationRow,
    ScanFindingRow,
    SecretRefRow,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --- assets & authorization ---------------------------------------------

class AssetRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    def save(self, asset: Asset) -> None:
        with self._sf() as s:
            row = s.get(AssetRow, asset.asset_id)
            if row is None:
                row = AssetRow(asset_id=asset.asset_id)
                s.add(row)
            row.kind = asset.kind
            row.owner = asset.owner
            row.environment = asset.environment
            conn = asset.connection
            row.conn_host = conn.host if conn else None
            row.conn_port = conn.port if conn else None
            row.conn_user = conn.user if conn else None
            row.conn_key_ref = conn.key_ref if conn else None
            a = asset.authorization
            row.authorizations.append(AuthorizationRow(
                attestation_sig=a.attestation_sig, granted_by=a.granted_by,
                granted_at=a.granted_at, expires_at=a.expires_at,
            ))
            s.commit()

    def get(self, asset_id: str) -> Asset | None:
        with self._sf() as s:
            row = s.get(AssetRow, asset_id)
            if row is None or not row.authorizations:
                return None
            return _to_asset(row)

    def all(self) -> list[Asset]:
        with self._sf() as s:
            rows = s.execute(select(AssetRow)).scalars().all()
            return [_to_asset(r) for r in rows if r.authorizations]

    def load_registry(self) -> AssetRegistry:
        reg = AssetRegistry()
        for asset in self.all():
            reg.register(asset)
        return reg


class PersistentAssetRegistry:
    """DB-backed asset registry (duck-types AssetRegistry). Every lookup queries
    the DB, so an asset onboarded by another process (e.g. the register-vps CLI)
    is immediately visible to a running engine, and registrations survive
    restarts."""

    def __init__(self, repo: AssetRepository) -> None:
        self._repo = repo

    def register(self, asset: Asset) -> None:
        self._repo.save(asset)

    def get(self, asset_id: str) -> Asset | None:
        return self._repo.get(asset_id)

    def all(self) -> list[Asset]:
        return self._repo.all()

    def require_authorized(self, asset_id: str, now: datetime) -> Asset:
        return _require_authorized(self._repo.get(asset_id), asset_id, now)


def _to_asset(row: AssetRow) -> Asset:
    latest = max(row.authorizations, key=lambda a: a.granted_at)
    connection = None
    if row.conn_host:
        connection = ConnectionInfo(
            host=row.conn_host, key_ref=row.conn_key_ref or "",
            port=row.conn_port or 22, user=row.conn_user or "root",
        )
    return Asset(
        asset_id=row.asset_id, kind=row.kind, owner=row.owner, environment=row.environment,
        authorization=Authorization(
            attestation_sig=latest.attestation_sig, granted_by=latest.granted_by,
            granted_at=latest.granted_at, expires_at=latest.expires_at,
        ),
        connection=connection,
    )


# --- secret references (ciphertext only) --------------------------------

class SecretRefRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    def put(self, ref: str, ciphertext: bytes, kms_key_id: str) -> None:
        with self._sf() as s:
            row = s.get(SecretRefRow, ref) or SecretRefRow(ref=ref)
            row.ciphertext = ciphertext
            row.kms_key_id = kms_key_id
            row.created_at = _utcnow()
            s.add(row)
            s.commit()

    def get_ciphertext(self, ref: str) -> tuple[bytes, str] | None:
        with self._sf() as s:
            row = s.get(SecretRefRow, ref)
            return (row.ciphertext, row.kms_key_id) if row else None


# --- approvals ----------------------------------------------------------

class ApprovalRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    def save(self, req: ApprovalRequest) -> None:
        with self._sf() as s:
            row = s.get(ApprovalRow, req.change_set_id) or ApprovalRow(
                change_set_id=req.change_set_id)
            row.resolved_commands = list(req.resolved_commands)
            row.blast_radius = req.blast_radius
            row.source_ref = req.source_ref
            row.requested_at = req.requested_at
            row.expires_at = req.expires_at
            row.approvals_required = req.approvals_required
            row.unlock_after = req.unlock_after
            row.state = req.state.value
            row.precondition_met = req.precondition_met
            # sync votes (distinct approvers)
            existing = {v.approver for v in row.votes}
            for approver in req.approvers:
                if approver not in existing:
                    row.votes.append(ApprovalVoteRow(approver=approver, created_at=_utcnow()))
            s.add(row)
            s.commit()

    def get(self, change_set_id: str) -> ApprovalRequest | None:
        with self._sf() as s:
            row = s.get(ApprovalRow, change_set_id)
            if row is None:
                return None
            req = ApprovalRequest(
                change_set_id=row.change_set_id,
                resolved_commands=list(row.resolved_commands),
                blast_radius=row.blast_radius, source_ref=row.source_ref,
                requested_at=row.requested_at, expires_at=row.expires_at,
                approvals_required=row.approvals_required, unlock_after=row.unlock_after,
                state=ApprovalState(row.state), precondition_met=row.precondition_met,
            )
            req.approvers = [v.approver for v in row.votes]
            return req

    def load_gate(self) -> ApprovalGate:
        gate = ApprovalGate()
        with self._sf() as s:
            ids = s.execute(select(ApprovalRow.change_set_id)).scalars().all()
        for cs_id in ids:
            req = self.get(cs_id)
            if req is not None:
                gate.request(req)
        return gate

    def summaries(self) -> list[dict]:
        """Lightweight listing for an operator UI: id, state, blast radius, ref."""
        with self._sf() as s:
            rows = s.execute(select(ApprovalRow).order_by(ApprovalRow.requested_at)).scalars().all()
            return [{"change_set_id": r.change_set_id, "state": r.state,
                     "blast_radius": r.blast_radius, "source_ref": r.source_ref,
                     "approvals_required": r.approvals_required,
                     "approvers": [v.approver for v in r.votes]} for r in rows]


# --- scan findings ------------------------------------------------------

class ScanFindingRepository:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    def save(self, findings: HostFindings, *, scanned_at: datetime | None = None) -> None:
        with self._sf() as s:
            s.add(ScanFindingRow(
                asset_id=findings.asset_id, scanned_at=scanned_at or _utcnow(),
                installed_packages=dict(findings.installed_packages),
                applied_patches=list(findings.applied_patches),
                misconfigurations=list(findings.misconfigurations),
            ))
            s.commit()

    def latest(self, asset_id: str) -> HostFindings | None:
        with self._sf() as s:
            row = s.execute(
                select(ScanFindingRow).where(ScanFindingRow.asset_id == asset_id)
                .order_by(ScanFindingRow.scanned_at.desc()).limit(1)
            ).scalar_one_or_none()
            if row is None:
                return None
            return HostFindings(
                asset_id=row.asset_id,
                installed_packages=dict(row.installed_packages),
                applied_patches=list(row.applied_patches),
                misconfigurations=list(row.misconfigurations),
            )


# --- audit store (satisfies audit.log.AuditStore protocol) --------------

class SqlAuditStore:
    """Durable, hash-chained audit store. ``ts`` is persisted as the exact
    isoformat string used in the hash so ``AuditLog.verify()`` holds after a
    reload."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    def append(self, rec: AuditRecord) -> None:
        with self._sf() as s:
            s.add(AuditRow(
                ts=rec.ts.isoformat(), actor=rec.actor, event=rec.event,
                payload=rec.payload, prev_hash=rec.prev_hash, this_hash=rec.this_hash,
            ))
            s.commit()

    def all(self) -> list[AuditRecord]:
        with self._sf() as s:
            rows = s.execute(select(AuditRow).order_by(AuditRow.seq)).scalars().all()
            return [
                AuditRecord(
                    ts=datetime.fromisoformat(r.ts), actor=r.actor, event=r.event,
                    payload=r.payload, prev_hash=r.prev_hash, this_hash=r.this_hash,
                )
                for r in rows
            ]

    def last_hash(self) -> str:
        with self._sf() as s:
            row = s.execute(
                select(AuditRow).order_by(AuditRow.seq.desc()).limit(1)
            ).scalar_one_or_none()
            return row.this_hash if row else GENESIS
