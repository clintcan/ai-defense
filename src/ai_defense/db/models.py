"""SQLAlchemy 2.0 table definitions (CLAUDE.md component: db).

Stores the asset registry + authorization ledger, secret *references*
(ciphertext + key id — never plaintext), approvals and their votes, scan
findings, advisories/remediations, and the hash-chained audit log.

Note on ``audit_log.ts``: it is stored as the exact ISO-8601 string used when
the record's hash was computed, so the chain still verifies after a reload
(SQLite would otherwise drop the timezone on a DateTime column and change the
hash material).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator):
    """Always persist and return timezone-aware UTC datetimes.

    SQLite has no native timezone support, so a plain ``DateTime`` round-trips as
    a naive value and then can't be compared against tz-aware ``now``. This
    decorator normalizes on the way in and out: naive values are assumed UTC.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class AssetRow(Base):
    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    owner: Mapped[str] = mapped_column(String(128))
    environment: Mapped[str] = mapped_column(String(64), index=True)

    authorizations: Mapped[list[AuthorizationRow]] = relationship(
        back_populates="asset", cascade="all, delete-orphan",
    )


class AuthorizationRow(Base):
    __tablename__ = "authorizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.asset_id"), index=True)
    attestation_sig: Mapped[str] = mapped_column(Text)
    granted_by: Mapped[str] = mapped_column(String(128))
    granted_at: Mapped[datetime] = mapped_column(UtcDateTime)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)

    asset: Mapped[AssetRow] = relationship(back_populates="authorizations")


class SecretRefRow(Base):
    """Only ciphertext + the KMS/key id that wraps it. NEVER plaintext."""

    __tablename__ = "secret_refs"

    ref: Mapped[str] = mapped_column(String(256), primary_key=True)
    ciphertext: Mapped[bytes] = mapped_column()
    kms_key_id: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class ApprovalRow(Base):
    __tablename__ = "approvals"

    change_set_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    resolved_commands: Mapped[list] = mapped_column(JSON)
    blast_radius: Mapped[int] = mapped_column(Integer)
    source_ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(UtcDateTime)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime)
    approvals_required: Mapped[int] = mapped_column(Integer, default=1)
    unlock_after: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="pending")
    precondition_met: Mapped[bool] = mapped_column(Boolean, default=False)

    votes: Mapped[list[ApprovalVoteRow]] = relationship(
        back_populates="approval", cascade="all, delete-orphan",
    )


class ApprovalVoteRow(Base):
    __tablename__ = "approval_votes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    change_set_id: Mapped[str] = mapped_column(ForeignKey("approvals.change_set_id"), index=True)
    approver: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)

    approval: Mapped[ApprovalRow] = relationship(back_populates="votes")


class ScanFindingRow(Base):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(String(128), index=True)
    scanned_at: Mapped[datetime] = mapped_column(UtcDateTime)
    installed_packages: Mapped[dict] = mapped_column(JSON)   # name -> version
    applied_patches: Mapped[list] = mapped_column(JSON)
    misconfigurations: Mapped[list] = mapped_column(JSON)


class AdvisoryRow(Base):
    __tablename__ = "advisories"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(64))
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)


class RemediationRow(Base):
    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(String(32), index=True)
    asset_id: Mapped[str] = mapped_column(String(128), index=True)
    action_type: Mapped[str] = mapped_column(String(32))   # patch | mitigation | ...
    status: Mapped[str] = mapped_column(String(32), default="planned")
    change_set_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime)


class AuditRow(Base):
    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[str] = mapped_column(String(40))            # exact isoformat() for hashing
    actor: Mapped[str] = mapped_column(String(128))
    event: Mapped[str] = mapped_column(String(32))
    payload: Mapped[dict] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64))
    this_hash: Mapped[str] = mapped_column(String(64), index=True)
