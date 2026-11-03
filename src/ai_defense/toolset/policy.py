"""Policy engine — the enforcement point (CLAUDE.md component: Toolset Layer).

Allow/deny lists, approval requirements, rate limits, change windows, and
blast-radius caps live HERE, not in the prompt. A jailbroken or confused model
still cannot exceed what this layer permits.

Default deny: an action is refused unless an explicit rule allows it.

Config shape (see config/policy.example.yaml):
    autonomous_action_classes: [discovery, scan, protective]
    blast_radius_caps: {patch_fleet: 500, ...}
    approvals: {patch_fleet: {required: 1, after: canary_health_ok}, ...}
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
    unlock_after: str | None = None


_DEFAULT_AUTONOMOUS = {
    ActionClass.DISCOVERY.value,
    ActionClass.SCAN.value,
    ActionClass.PROTECTIVE.value,
}


class PolicyEngine:
    """Evaluates an Intent against loaded policy. Fail safe -> DENY on doubt."""

    def __init__(self, config: dict | None = None) -> None:
        self._config = config or {}

    def _autonomous(self) -> set[str]:
        return set(self._config.get("autonomous_action_classes", _DEFAULT_AUTONOMOUS))

    def _cap_for(self, action_class: ActionClass) -> int | None:
        return self._config.get("blast_radius_caps", {}).get(action_class.value)

    def _approvals_for(self, action_class: ActionClass) -> dict | None:
        return self._config.get("approvals", {}).get(action_class.value)

    def evaluate(self, intent: Intent, *, blast_radius: int) -> PolicyVerdict:
        ac = intent.action_class

        # Blast-radius cap applies to every class that has one (read-only too).
        cap = self._cap_for(ac)
        if cap is not None and blast_radius > cap:
            return PolicyVerdict(
                Decision.DENY,
                f"blast radius {blast_radius} exceeds cap {cap} for {ac.value}",
            )

        # Autonomous (read-only / protective) classes need no human approval.
        if ac.value in self._autonomous():
            return PolicyVerdict(Decision.ALLOW, f"{ac.value} is autonomous within policy")

        # Otherwise an explicit approvals rule must exist (default deny).
        approvals = self._approvals_for(ac)
        if approvals is None:
            return PolicyVerdict(
                Decision.DENY,
                f"no approval rule configured for {ac.value} (default deny)",
            )

        return PolicyVerdict(
            Decision.REQUIRE_APPROVAL,
            f"{ac.value} requires human approval",
            approvals_required=int(approvals.get("required", 1)),
            unlock_after=approvals.get("after"),
        )

    @staticmethod
    def is_autonomous_class(action_class: ActionClass) -> bool:
        return action_class.value in _DEFAULT_AUTONOMOUS
