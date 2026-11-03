"""Audit, logging & rollback (CLAUDE.md component 7).

Append-only, tamper-evident log of every intent, approval decision, executed
command, and result. Secrets are always redacted. Each change links to its
CVE/advisory, approver, and target set, with rollback info where feasible.
"""
