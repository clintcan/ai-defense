"""Secrets vault (CLAUDE.md component 2). Credentials never touch the LLM.

Stores only ciphertext + key references in the DB. Secrets are resolved and
decrypted at call time by the toolset, used in-process, and never returned to
the planner or written to logs. Prefer short-lived STS/OIDC creds and SSH
certificates over long-lived static keys.
"""
