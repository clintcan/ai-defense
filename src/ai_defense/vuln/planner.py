"""Remediation planner. Builds Intents; never invents a fix.

For each finding:
  * patch available   -> propose vendor update via cloud/ssh patch tools
  * no patch yet       -> propose the PUBLISHED mitigation (labeled temporary,
                          with a tracking item to apply the patch once released)
  * neither available  -> escalate to a human; do not improvise

Every proposed action cites its source advisory so a human can verify it before
approval.
"""

from __future__ import annotations

from ..toolset.intents import Intent


class RemediationPlanner:
    def plan(self, advisory: dict, affected: list[str]) -> list[Intent]:
        raise NotImplementedError
