"""Authenticated scanner (CLAUDE.md component 5). Strictly READ-ONLY.

Logs into managed hosts with vault-issued creds (resolved by the toolset) and
inspects local state to detect missing patches and misconfigurations. It only
runs query/check-mode commands from the catalog's read-only subset. It CANNOT
install, modify, or restart anything — detection and remediation are separate
code paths. It detects and reports; it never decides or applies a fix.
"""
