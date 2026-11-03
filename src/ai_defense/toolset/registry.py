"""Tool registry — the ONLY surface the planner can reach.

Default deny: a provider method or SSH template is unreachable until it is
wrapped here as a reviewed, typed tool. There is no generic "run any API call"
or "run any command" tool, by design (CLAUDE.md hard rule #3 and #5).

The dispatch path for every intent is:
    validate schema → PolicyEngine.evaluate → (approval gate if required)
    → resolve secrets from vault → execute → redact → audit → ToolResult
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .intents import Intent, ToolResult


class Executor(Protocol):
    """A registered tool's execution function. Receives validated params and a
    secret-resolver callback; MUST NOT accept or return raw secrets."""

    def __call__(self, params: dict[str, Any], *, resolve_secret: Callable[[str], Any]) -> ToolResult: ...


@dataclass(frozen=True)
class ToolSpec:
    name: str
    schema: dict                 # JSON schema for params
    executor: Executor
    read_only: bool
    describe_blast_radius: Callable[[dict], int] | None = None


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

    def dispatch(self, intent: Intent) -> ToolResult:
        """End-to-end dispatch. TODO: wire policy, approval, vault, audit."""
        raise NotImplementedError("dispatch pipeline not yet implemented")
