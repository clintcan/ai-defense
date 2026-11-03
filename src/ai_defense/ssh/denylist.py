"""Destructive-pattern denylist — blocks even if a human approves.

These patterns are refused unconditionally at the executor. Belt-and-braces on
top of the allowlist catalog.
"""

from __future__ import annotations

import re

DENY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\brm\s+-rf\s+/(?!\w)"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\b.*\bof=/dev/"),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"),       # fork bomb
    re.compile(r"\b(systemctl\s+(stop|disable)\s+(auditd|firewalld|ufw))\b"),
    re.compile(r"\buserdel\b.*--force"),
    re.compile(r">\s*/dev/sd[a-z]"),
]


def is_denied(command: str) -> bool:
    return any(p.search(command) for p in DENY_PATTERNS)
