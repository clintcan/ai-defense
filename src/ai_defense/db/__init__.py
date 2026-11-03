"""Persistence. Stores ciphertext + key references ONLY for secrets, plus the
asset registry, authorization ledger, approvals, scan findings, and audit log.
Never stores plaintext secrets. See .gitignore for files that must never be
committed.
"""

from .database import create_all, init_db, make_engine, make_session_factory
from .repositories import (
    ApprovalRepository,
    AssetRepository,
    PersistentAssetRegistry,
    ScanFindingRepository,
    SecretRefRepository,
    SqlAuditStore,
)

__all__ = [
    "init_db",
    "make_engine",
    "create_all",
    "make_session_factory",
    "AssetRepository",
    "PersistentAssetRegistry",
    "ApprovalRepository",
    "ScanFindingRepository",
    "SecretRefRepository",
    "SqlAuditStore",
]
