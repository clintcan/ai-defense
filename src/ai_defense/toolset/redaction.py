"""Secret redaction — defense in depth before anything leaves the toolset.

The executor is responsible for not returning secrets, but the dispatcher also
scrubs every secret value it resolved out of the result and any audit payload.
This guarantees a secret can never reach the planner or the audit log even if a
tool implementation is careless. See CLAUDE.md "Trust boundaries".
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from .intents import ToolResult

PLACEHOLDER = "***REDACTED***"


def redact_text(text: str | None, secrets: set[str]) -> str | None:
    if text is None:
        return None
    for s in secrets:
        if s:  # never replace empty string (would corrupt everything)
            text = text.replace(s, PLACEHOLDER)
    return text


def redact_value(value: Any, secrets: set[str]) -> Any:
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, dict):
        return {k: redact_value(v, secrets) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(v, secrets) for v in value)
    return value


def redact_result(result: ToolResult, secrets: set[str]) -> ToolResult:
    return replace(
        result,
        summary=redact_text(result.summary, secrets) or "",
        data=redact_value(result.data, secrets),
        resolved_command=redact_text(result.resolved_command, secrets),
    )
