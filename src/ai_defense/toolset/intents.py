"""Typed intent schemas — the JSON contract between the planner and the toolset.

An *intent* is what the LLM emits. It is data, never code, and never carries a
credential. The toolset validates it, resolves secrets at execution time, and
executes. See CLAUDE.md "Core security model".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ActionClass(str, Enum):
    """Maps to the approval table in CLAUDE.md."""

    DISCOVERY = "discovery"          # read-only, autonomous within policy
    SCAN = "scan"                    # authenticated read-only scanner
    PROTECTIVE = "protective"        # snapshot/backup before a gated change
    MITIGATE_CANARY = "mitigate_canary"
    MITIGATE_FLEET = "mitigate_fleet"
    PATCH_CANARY = "patch_canary"
    PATCH_FLEET = "patch_fleet"
    EMERGENCY = "emergency"
    CLEANUP = "cleanup"              # e.g. deleting a pre-change snapshot once stable


@dataclass(frozen=True)
class Intent:
    """A single proposed action from the planner.

    ``tool`` must name a registered toolset entry; ``params`` must satisfy that
    tool's schema. ``targets`` are asset IDs that MUST already be registered and
    authorized. ``reason`` and ``source_ref`` support human review (e.g. the CVE
    or advisory the action is derived from).
    """

    tool: str
    params: dict[str, Any]
    targets: list[str]
    action_class: ActionClass
    reason: str
    source_ref: str | None = None          # e.g. "CVE-2026-1234" / advisory URL
    requested_by: str = "planner"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolResult:
    """What the toolset returns to the planner. Secrets are always redacted."""

    ok: bool
    tool: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    resolved_command: str | None = None     # the command that ran, secrets removed
    audit_id: str | None = None
