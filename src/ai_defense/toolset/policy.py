"""Policy engine — the enforcement point (CLAUDE.md component: Toolset Layer).

Allow/deny lists, approval requirements, rate limits, change windows, and
blast-radius caps live HERE, not in the prompt. A jailbroken or confused model
still cannot exceed what this layer permits.

Default deny: an action is refused unless an explicit rule allows it.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .intents import ActionClass, Intent


class Decision(str, Enum):
    ALLOW = "allow"                  # may execute autonomously
    REQUIRE_APPROVAL = "approval"    # needs a human approval first
    DENY = "deny"                    # blocked unconditionally


@dataclass(frozen=True)
class PolicyVerdict:
    decision: Decision
    reason: str
    approvals_required: int = 0


# Action classes that may run without human approval (read-only / protective).
_AUTONOMOUS = {
    ActionClass.DISCOVERY,
    ActionClass.SCAN,
    ActionClass.PROTECTIVE,
}


class PolicyEngine:
    """Evaluates an Intent against loaded policy. Fail safe → DENY on doubt."""

    def __init__(self, config: dict) -> None:
        self._config = config

    def evaluate(self, intent: Intent) -> PolicyVerdict:
        """Return a verdict. TODO: implement the full ruleset.

        Order of checks (all must pass):
          1. All targets registered + authorization attestation valid/unexpired.
          2. Tool is allowlisted; params match the tool schema.
          3. Command (if SSH) is not on the destructive denylist.
          4. Blast radius within the cap for this action class.
          5. Within an approved change window (unless EMERGENCY → elevated).
          6. Rate / concurrency limits not exceeded.
        """
        raise NotImplementedError("policy ruleset not yet implemented")

    @staticmethod
    def is_autonomous(action_class: ActionClass) -> bool:
        return action_class in _AUTONOMOUS
