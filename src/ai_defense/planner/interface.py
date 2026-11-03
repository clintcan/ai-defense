"""Planner <-> toolset interface.

Converts model-proposed actions into validated `Intent`s and relays redacted
results back. Keep this module free of any provider SDK, SSH client, or secret
material — those live behind the toolset. See CLAUDE.md "Trust boundaries".
"""

from __future__ import annotations

from ..toolset.dispatch import Dispatcher
from ..toolset.intents import Intent, ToolResult


class PlannerInterface:
    """The single surface the LLM-facing layer may call. It can enumerate the
    allowlisted tools and submit intents; it never sees secrets, and every
    result it receives has already passed through redaction."""

    def __init__(self, dispatcher: Dispatcher) -> None:
        self._dispatcher = dispatcher

    def available_tools(self) -> list[str]:
        """Tool names the planner may propose. No raw SDK surface is exposed."""
        return self._dispatcher.registry.names()

    def submit(self, intent: Intent) -> ToolResult:
        """Hand an intent to the enforcement layer and return a redacted result."""
        return self._dispatcher.dispatch(intent)
