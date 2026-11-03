"""Dispatch pipeline — the one path every intent travels (CLAUDE.md core model).

    validate -> authorize targets -> policy -> approval gate
    -> resolve secrets -> execute -> redact -> audit -> ToolResult

The planner only ever calls into this. Secrets are resolved here, used by the
tool in-process, and scrubbed from everything returned or logged. Any failure is
fail-safe: no execution, an ok=False result, and an audit record.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from ..approval.gate import ApprovalGate, ApprovalRequest, ApprovalState
from ..audit.log import AuditLog
from ..registry.assets import AssetRegistry
from ..vault.vault import Vault
from .intents import Intent, ToolResult
from .policy import Decision, PolicyEngine
from .ratelimit import RateLimiter
from .redaction import redact_result, redact_value
from .registry import ToolCapability, ToolRegistry
from .validators import ValidationError, validate


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _intent_audit_payload(intent: Intent) -> dict[str, Any]:
    return {
        "tool": intent.tool,
        "action_class": intent.action_class.value,
        "targets": list(intent.targets),
        "reason": intent.reason,
        "source_ref": intent.source_ref,
        "requested_by": intent.requested_by,
        # params may reference a secret *name*, never a value; audited as-is.
        "params": intent.params,
    }


def default_change_set_id(intent: Intent) -> str:
    material = "|".join([
        intent.tool,
        ",".join(sorted(intent.targets)),
        repr(sorted(intent.params.items())),
        intent.source_ref or "",
    ])
    return "cs_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


class Dispatcher:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        policy: PolicyEngine,
        assets: AssetRegistry,
        approvals: ApprovalGate,
        vault: Vault,
        audit: AuditLog,
        clock: Callable[[], datetime] = _utcnow,
        approval_ttl: timedelta = timedelta(hours=1),
        change_set_id: Callable[[Intent], str] = default_change_set_id,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._registry = registry
        self._policy = policy
        self._assets = assets
        self._approvals = approvals
        self._vault = vault
        self._audit = audit
        self._clock = clock
        self._approval_ttl = approval_ttl
        self._change_set_id = change_set_id
        self._rate_limiter = rate_limiter

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    def dispatch(self, intent: Intent, *, actor: str = "planner") -> ToolResult:
        now = self._clock()
        self._audit.record(intent.requested_by, "intent", _intent_audit_payload(intent))

        # 1. Validate the intent shape against the registered tool schema.
        try:
            validate(intent, self._registry)
        except (ValidationError, KeyError) as exc:
            return self._deny(intent, f"validation failed: {exc}")

        spec = self._registry.get(intent.tool)

        # Declared tool capability must permit the claimed action class. This
        # blocks BOTH directions of mislabeling — a read-only tool claiming a
        # write class, and (critically) a mutating tool claiming an autonomous
        # class to skip approval. Enforced before policy, independent of it.
        if not spec.allows(intent.action_class):
            return self._deny(
                intent,
                f"tool '{intent.tool}' (capability={spec.capability.value}) may not "
                f"run under action class '{intent.action_class.value}'",
            )

        # 2. Authorization: every target must be registered and unexpired.
        try:
            for target in intent.targets:
                self._assets.require_authorized(target, now)
        except PermissionError as exc:
            return self._deny(intent, f"authorization: {exc}")

        # 3. Policy evaluation (blast radius, autonomy, approval requirement).
        blast = self._blast_radius(spec, intent)
        verdict = self._policy.evaluate(intent, blast_radius=blast)
        self._audit.record(actor, "policy", {
            "tool": intent.tool, "decision": verdict.decision.value,
            "reason": verdict.reason, "blast_radius": blast,
        })

        if verdict.decision is Decision.DENY:
            return self._deny(intent, verdict.reason)

        # 4. Approval gate for anything not autonomous.
        if verdict.decision is Decision.REQUIRE_APPROVAL:
            cs_id = self._change_set_id(intent)
            self._approvals.request(ApprovalRequest(
                change_set_id=cs_id,
                resolved_commands=[f"{intent.tool}({intent.params})"],
                blast_radius=blast,
                source_ref=intent.source_ref,
                requested_at=now,
                expires_at=now + self._approval_ttl,
                approvals_required=verdict.approvals_required,
                unlock_after=verdict.unlock_after,
            ))
            if not self._approvals.is_cleared(cs_id, now):
                state = self._approvals.state_for(cs_id, now)
                self._audit.record(actor, "approval", {
                    "tool": intent.tool, "change_set_id": cs_id, "state": state.value,
                })
                return ToolResult(
                    ok=False, tool=intent.tool,
                    summary=f"awaiting approval ({state.value})",
                    data={"change_set_id": cs_id, "approval_state": state.value,
                          "approvals_required": verdict.approvals_required,
                          "blast_radius": blast},
                )
            self._audit.record(actor, "approval", {
                "tool": intent.tool, "change_set_id": cs_id,
                "state": ApprovalState.APPROVED.value,
            })

        # 5. Resolve secrets (recording values for redaction) and execute.
        secrets_seen: set[str] = set()

        def resolve_secret(ref: str) -> Any:
            value = self._vault.resolve(ref, actor=actor, reason=intent.reason)
            if value is not None:
                secrets_seen.add(str(value))
            return value

        # Rate limit & concurrency caps apply to mutating changes only, checked
        # atomically right before execution. A reservation holds a concurrency
        # slot until the finally releases it.
        reservation = None
        if self._rate_limiter is not None and spec.capability is ToolCapability.MUTATING:
            reservation, reason = self._rate_limiter.try_begin(intent.targets, now)
            if reservation is None:
                return self._deny(intent, f"rate limit: {reason}")

        try:
            result = spec.executor(intent.params, resolve_secret=resolve_secret)
        except Exception as exc:  # noqa: BLE001 - deliberate fail-safe: any tool error becomes a denied result, never a leak or a partial success
            return self._deny(intent, f"execution error: {type(exc).__name__}")
        finally:
            if reservation is not None:
                self._rate_limiter.end(reservation)

        # 6. Redact any resolved secret from the result, then audit + return.
        result = redact_result(result, secrets_seen)
        rec = self._audit.record(actor, "result", {
            "tool": intent.tool, "ok": result.ok,
            "summary": result.summary,
            "resolved_command": result.resolved_command,
            "data": redact_value(result.data, secrets_seen),
        })
        return replace(result, audit_id=rec.this_hash)

    # -- helpers ----------------------------------------------------------

    def _blast_radius(self, spec, intent: Intent) -> int:
        if spec.describe_blast_radius is not None:
            return int(spec.describe_blast_radius(intent.params))
        return len(intent.targets)

    def _deny(self, intent: Intent, reason: str) -> ToolResult:
        rec = self._audit.record("toolset", "deny", {"tool": intent.tool, "reason": reason})
        return ToolResult(ok=False, tool=intent.tool, summary=f"denied: {reason}",
                          data={"reason": reason}, audit_id=rec.this_hash)
