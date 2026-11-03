"""Persistence. Stores ciphertext + key references ONLY for secrets, plus the
asset registry, authorization ledger, approvals, scan findings, and audit log.
Never stores plaintext secrets. See .gitignore for files that must never be
committed.
"""
