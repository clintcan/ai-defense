"""Tool registry — the ONLY surface the planner can reach.

Default deny: a provider method or SSH template is unreachable until it is
wrapped here as a reviewed, typed tool. There is no generic "run any API call"
or "run any command" tool, by design (CLAUDE.md hard rule #3 and #5).

The dispatch path for every intent is:
    validate schema → PolicyEngine.evaluate → (approval gate if required)
    → resolve secrets from vault → execute → redact → audit → ToolResult
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from .intents import ActionClass, ToolResult


class ToolCapability(str, Enum):
    """What a tool is actually able to do. Declared at registration and enforced
    at dispatch, independently of the action class the planner claims. This is a
    defense-in-depth guard: a MUTATING tool can never be dispatched under an
    autonomous (read-only/protective) action class, so it can never bypass the
    approval gate by being mislabeled."""

    READ_ONLY = "read_only"      # discovery / authenticated scanning; no change
    PROTECTIVE = "protective"    # snapshot/backup before a change; autonomous-ok
    MUTATING = "mutating"        # changes a system; always needs approval


# Which action classes each capability may legitimately run under.
_ALLOWED_CLASSES: dict[ToolCapability, set[ActionClass]] = {
    ToolCapability.READ_ONLY: {ActionClass.DISCOVERY, ActionClass.SCAN},
    ToolCapability.PROTECTIVE: {ActionClass.PROTECTIVE},
    ToolCapability.MUTATING: {
        ActionClass.MITIGATE_CANARY, ActionClass.MITIGATE_FLEET,
        ActionClass.PATCH_CANARY, ActionClass.PATCH_FLEET,
        ActionClass.EMERGENCY, ActionClass.CLEANUP,
    },
}


class Executor(Protocol):
    """A registered tool's execution function. Receives validated params and a
    secret-resolver callback; MUST NOT accept or return raw secrets."""

    def __call__(
        self, params: dict[str, Any], *, resolve_secret: Callable[[str], Any]
    ) -> ToolResult: ...


@dataclass(frozen=True)
class ToolSpec:
    name: str
    schema: dict                 # JSON schema for params
    executor: Executor
    capability: ToolCapability
    describe_blast_radius: Callable[[dict], int] | None = None

    @property
    def read_only(self) -> bool:
        return self.capability is ToolCapability.READ_ONLY

    def allows(self, action_class: ActionClass) -> bool:
        return action_class in _ALLOWED_CLASSES[self.capability]


class ToolRegistry:
    """Holds the allowlisted tools. Nothing executes that isn't registered."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool already registered: {spec.name}")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise KeyError(f"unknown tool (not allowlisted): {name}")
        return self._tools[name]

    def names(self) -> list[str]:
        return sorted(self._tools)
