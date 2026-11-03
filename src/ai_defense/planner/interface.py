"""Planner <-> toolset interface.

Converts model-proposed actions into validated `Intent`s and relays redacted
results back. Keep this module free of any provider SDK, SSH client, or secret
material — those live behind the toolset. See CLAUDE.md "Trust boundaries".
"""

from __future__ import annotations

from ..toolset.intents import Intent, ToolResult
from ..toolset.registry import ToolRegistry


class PlannerInterface:
    def __init__(self, registry: ToolRegistry) -> None:
        self._registry = registry

    def available_tools(self) -> list[str]:
        """Tool names the planner may propose. No raw SDK surface is exposed."""
        return self._registry.names()

    def submit(self, intent: Intent) -> ToolResult:
        """Hand an intent to the enforcement layer and return a redacted result."""
        return self._registry.dispatch(intent)
