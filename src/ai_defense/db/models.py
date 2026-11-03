"""ORM/table definitions. TODO: choose engine (SQLAlchemy/SQLite->Postgres).

Tables (sketch): assets, authorizations, secret_refs (ciphertext + kms key id),
command_templates, approvals, scan_findings, advisories, remediations,
audit_log (hash-chained).
"""
