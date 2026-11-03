"""Remediation planner. Builds Intents from correlated findings; never invents a fix.

For each finding:
  * patch available  -> a patch Intent (vendor update via the SSH patch tool)
  * no patch, has a published mitigation -> a mitigation item, flagged for human
    action and labeled temporary, with a tracking note to patch once released
  * neither           -> escalate to a human; do not improvise

Items are prioritized: CISA KEV first, then CVSS, then whether a patch exists
(actionable now) — so the most urgent, actionable work surfaces at the top.
Every item cites its source advisory for human verification before approval.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from ..scanner.scanner import HostFindings
from ..toolset.intents import ActionClass, Intent
from .correlate import VulnFinding, correlate
from .feeds import Advisory


class RemediationKind(str, Enum):
    PATCH = "patch"
    MITIGATION = "mitigation"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class RemediationItem:
    cve_id: str
    asset_id: str
    package: str
    kind: RemediationKind
    priority: float
    source_ref: str
    note: str
    requires_human: bool
    intent: Intent | None = None      # present for auto-actionable patch items
    tracking: str | None = None       # follow-up to apply the real patch later
    metadata: dict = field(default_factory=dict)


def _priority(advisory: Advisory, patch_available: bool) -> float:
    score = 0.0
    if advisory.kev:
        score += 1000.0                         # actively exploited -> top
    score += (advisory.cvss or 0.0) * 10.0      # 0..100
    if patch_available:
        score += 1.0                            # tie-break: actionable now
    return score


class RemediationPlanner:
    """Produces a prioritized remediation plan from advisories + observed state.

    ``key_ref_for`` maps an asset id to its SSH key's vault reference (used only
    to build the patch Intent's params; the value is never resolved here).
    ``patch_action_class`` defaults to a canary rollout.
    """

    def __init__(
        self,
        *,
        key_ref_for: Callable[[str], str],
        patch_tool: str = "patch.apply_security_update",
        patch_action_class: ActionClass = ActionClass.PATCH_CANARY,
    ) -> None:
        self._key_ref_for = key_ref_for
        self._patch_tool = patch_tool
        self._patch_action_class = patch_action_class

    def plan(
        self, advisories: list[Advisory], inventory: list[HostFindings],
    ) -> list[RemediationItem]:
        items = [self._item(f) for f in correlate(advisories, inventory)]
        items.sort(key=lambda it: it.priority, reverse=True)
        return items

    def _item(self, f: VulnFinding) -> RemediationItem:
        adv = f.advisory
        prio = _priority(adv, f.patch_available)

        if f.patch_available:
            intent = Intent(
                tool=self._patch_tool,
                params={
                    "host": f.asset_id,
                    "package": f.package,
                    "key_ref": self._key_ref_for(f.asset_id),
                },
                targets=[f.asset_id],
                action_class=self._patch_action_class,
                reason=f"remediate {f.cve_id}: upgrade {f.package} "
                       f"{f.installed_version} -> {f.fixed_version}",
                source_ref=f.cve_id,
            )
            return RemediationItem(
                cve_id=f.cve_id, asset_id=f.asset_id, package=f.package,
                kind=RemediationKind.PATCH, priority=prio, source_ref=f.cve_id,
                note=f"Upgrade {f.package} to {f.fixed_version}.",
                requires_human=False, intent=intent,
            )

        if adv.mitigation:
            return RemediationItem(
                cve_id=f.cve_id, asset_id=f.asset_id, package=f.package,
                kind=RemediationKind.MITIGATION, priority=prio, source_ref=f.cve_id,
                note=f"TEMPORARY mitigation (no patch released): {adv.mitigation}",
                requires_human=True,
                tracking=f"Apply the vendor patch for {f.cve_id} on {f.asset_id} "
                         f"once {f.package} ships a fixed version.",
            )

        return RemediationItem(
            cve_id=f.cve_id, asset_id=f.asset_id, package=f.package,
            kind=RemediationKind.ESCALATE, priority=prio, source_ref=f.cve_id,
            note=f"No patch and no published mitigation for {f.cve_id} affecting "
                 f"{f.package} {f.installed_version}. Escalate for human decision.",
            requires_human=True,
        )
