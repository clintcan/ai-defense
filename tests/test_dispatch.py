"""End-to-end dispatch pipeline tests with in-memory fakes.

Covers: autonomous read-only execution, write-needs-approval, approval then
execute, default-deny, blast-radius cap, unregistered/expired authorization,
read-only-tool-misused-as-write, execution error fail-safe, secret redaction in
both result and audit, and audit-chain integrity.
"""

from datetime import UTC, datetime, timedelta

from ai_defense.approval.gate import ApprovalGate
from ai_defense.audit.log import AuditLog
from ai_defense.registry.assets import Asset, AssetRegistry, Authorization
from ai_defense.toolset.dispatch import Dispatcher
from ai_defense.toolset.intents import ActionClass, Intent, ToolResult
from ai_defense.toolset.policy import PolicyEngine
from ai_defense.toolset.ratelimit import InMemoryRateBackend, RateLimiter
from ai_defense.toolset.redaction import PLACEHOLDER
from ai_defense.toolset.registry import ToolCapability, ToolRegistry, ToolSpec
from ai_defense.vault.vault import SecretsBackend, Vault

NOW = datetime(2026, 11, 3, tzinfo=UTC)

POLICY_CONFIG = {
    "autonomous_action_classes": ["discovery", "scan", "protective"],
    "blast_radius_caps": {"patch_fleet": 3, "scan": 100},
    "approvals": {
        "patch_canary": {"required": 1},
        "patch_fleet": {"required": 2, "after": "canary_health_ok"},
    },
}


class FakeBackend(SecretsBackend):
    def __init__(self, secrets):
        self._secrets = secrets
        self.access_log = []

    def resolve(self, ref):
        return self._secrets[ref]

    def audit_access(self, ref, *, actor, reason):
        self.access_log.append((ref, actor, reason))


def _registry():
    reg = ToolRegistry()

    def read_exec(params, *, resolve_secret):
        return ToolResult(ok=True, tool="scan.host", summary="scanned",
                          data={"packages": 42})

    def patch_exec(params, *, resolve_secret):
        key = resolve_secret("ssh-key/web")          # pulls the secret in-process
        # A careless tool that leaks the secret into its output — the dispatcher
        # must still redact it.
        return ToolResult(ok=True, tool="patch.apply", summary=f"applied with {key}",
                          data={"used_key": key, "host": params.get("host")},
                          resolved_command=f"ssh -i {key} host apt-get upgrade")

    reg.register(ToolSpec("scan.host", schema={}, executor=read_exec,
                          capability=ToolCapability.READ_ONLY))
    reg.register(ToolSpec("patch.apply", schema={}, executor=patch_exec,
                          capability=ToolCapability.MUTATING))
    return reg


def _assets(expired=False):
    reg = AssetRegistry()
    exp = NOW - timedelta(days=1) if expired else NOW + timedelta(days=30)
    reg.register(Asset(
        asset_id="web-prod-01", kind="ssh-host", owner="t", environment="web-prod",
        authorization=Authorization("sig", "lead", NOW - timedelta(days=1), exp),
    ))
    return reg


def _dispatcher(assets=None, approvals=None, vault=None, audit=None, rate_limiter=None):
    return Dispatcher(
        registry=_registry(),
        policy=PolicyEngine(POLICY_CONFIG),
        assets=assets or _assets(),
        approvals=approvals or ApprovalGate(),
        vault=vault or Vault(FakeBackend({"ssh-key/web": "SUPER-SECRET-KEY"})),
        audit=audit or AuditLog(clock=lambda: NOW),
        clock=lambda: NOW,
        rate_limiter=rate_limiter,
    )


def _approved_dispatcher(rate_limiter):
    """A dispatcher whose approvals auto-clear, to exercise the execute path."""
    approvals = ApprovalGate()
    disp = _dispatcher(approvals=approvals, rate_limiter=rate_limiter)
    return disp, approvals


def _approve(disp, approvals, intent):
    cs_id = disp.dispatch(intent).data["change_set_id"]
    approvals.decide(cs_id, "lead", approve=True, now=NOW)


def _scan_intent():
    return Intent(tool="scan.host", params={"host": "web-prod-01"},
                  targets=["web-prod-01"], action_class=ActionClass.SCAN,
                  reason="inventory")


def _patch_intent(action_class=ActionClass.PATCH_CANARY, targets=("web-prod-01",)):
    return Intent(tool="patch.apply", params={"host": "web-prod-01"},
                  targets=list(targets), action_class=action_class,
                  reason="CVE-2026-1234", source_ref="CVE-2026-1234")


# --- autonomous read-only -----------------------------------------------

def test_autonomous_scan_executes():
    res = _dispatcher().dispatch(_scan_intent())
    assert res.ok and res.summary == "scanned"
    assert res.audit_id


# --- write needs approval -----------------------------------------------

def test_write_without_approval_is_pending_not_executed():
    res = _dispatcher().dispatch(_patch_intent())
    assert not res.ok
    assert "awaiting approval" in res.summary
    assert res.data["approval_state"] == "pending"


def test_write_executes_after_approval():
    approvals = ApprovalGate()
    disp = _dispatcher(approvals=approvals)
    intent = _patch_intent()
    first = disp.dispatch(intent)                       # creates the request
    cs_id = first.data["change_set_id"]
    approvals.decide(cs_id, "secops-lead", approve=True, now=NOW)
    res = disp.dispatch(intent)
    assert res.ok
    assert res.summary.endswith(PLACEHOLDER)            # "applied with ***REDACTED***"


def test_fleet_requires_two_and_canary_precondition():
    approvals = ApprovalGate()
    disp = _dispatcher(approvals=approvals)
    intent = _patch_intent(action_class=ActionClass.PATCH_FLEET)
    cs_id = disp.dispatch(intent).data["change_set_id"]
    approvals.decide(cs_id, "lead-1", approve=True, now=NOW)
    # one approval + precondition unmet -> still blocked
    assert not disp.dispatch(intent).ok
    approvals.decide(cs_id, "lead-2", approve=True, now=NOW)
    assert not disp.dispatch(intent).ok                 # needs canary_health_ok
    approvals.mark_precondition_met(cs_id)
    assert disp.dispatch(intent).ok


# --- denials -------------------------------------------------------------

def test_blast_radius_cap_denies_fleet():
    # PATCH_FLEET cap is 3; four targets must be denied before any approval.
    disp = Dispatcher(
        registry=_registry(), policy=PolicyEngine(POLICY_CONFIG),
        assets=_four_assets(), approvals=ApprovalGate(),
        vault=Vault(FakeBackend({"ssh-key/web": "x"})),
        audit=AuditLog(clock=lambda: NOW), clock=lambda: NOW,
    )
    intent = Intent(tool="patch.apply", params={}, targets=["h1", "h2", "h3", "h4"],
                    action_class=ActionClass.PATCH_FLEET, reason="r")
    res = disp.dispatch(intent)
    assert not res.ok and "blast radius" in res.data["reason"]


def test_unregistered_target_denied():
    intent = Intent(tool="scan.host", params={}, targets=["ghost"],
                    action_class=ActionClass.SCAN, reason="r")
    res = _dispatcher().dispatch(intent)
    assert not res.ok and "authorization" in res.data["reason"]


def test_expired_authorization_denied():
    res = _dispatcher(assets=_assets(expired=True)).dispatch(_scan_intent())
    assert not res.ok and "authorization" in res.data["reason"]


def test_default_deny_for_unconfigured_class():
    # EMERGENCY has no approvals rule in POLICY_CONFIG -> default deny.
    intent = _patch_intent(action_class=ActionClass.EMERGENCY)
    res = _dispatcher().dispatch(intent)
    assert not res.ok and "default deny" in res.data["reason"]


def test_read_only_tool_cannot_be_used_as_write():
    intent = Intent(tool="scan.host", params={}, targets=["web-prod-01"],
                    action_class=ActionClass.PATCH_CANARY, reason="r")
    res = _dispatcher().dispatch(intent)
    assert not res.ok and "may not run under action class" in res.summary


def test_mutating_tool_cannot_pose_as_autonomous_scan():
    # Approval-bypass guard: a MUTATING tool mislabeled with an autonomous
    # (read-only) action class must be refused BEFORE policy, so it can never
    # execute without approval.
    intent = Intent(tool="patch.apply", params={"host": "web-prod-01"},
                    targets=["web-prod-01"], action_class=ActionClass.SCAN,
                    reason="sneaky")
    res = _dispatcher().dispatch(intent)
    assert not res.ok
    assert "capability=mutating" in res.summary
    assert "may not run under action class 'scan'" in res.summary


def test_unknown_tool_denied():
    intent = Intent(tool="nope.evil", params={}, targets=["web-prod-01"],
                    action_class=ActionClass.SCAN, reason="r")
    res = _dispatcher().dispatch(intent)
    assert not res.ok and "validation failed" in res.summary


def test_execution_error_is_failsafe():
    reg = ToolRegistry()

    def boom(params, *, resolve_secret):
        raise RuntimeError("secret leak in message SUPER-SECRET-KEY")

    reg.register(ToolSpec("scan.host", schema={}, executor=boom,
                          capability=ToolCapability.READ_ONLY))
    disp = Dispatcher(registry=reg, policy=PolicyEngine(POLICY_CONFIG),
                      assets=_assets(), approvals=ApprovalGate(),
                      vault=Vault(FakeBackend({})), audit=AuditLog(clock=lambda: NOW),
                      clock=lambda: NOW)
    res = disp.dispatch(_scan_intent())
    assert not res.ok
    assert "SUPER-SECRET-KEY" not in res.summary       # internals not leaked
    assert res.summary == "denied: execution error: RuntimeError"


# --- secret containment & audit integrity -------------------------------

def test_secret_never_in_result_or_audit():
    audit = AuditLog(clock=lambda: NOW)
    approvals = ApprovalGate()
    disp = _dispatcher(approvals=approvals, audit=audit)
    intent = _patch_intent()
    cs_id = disp.dispatch(intent).data["change_set_id"]
    approvals.decide(cs_id, "lead", approve=True, now=NOW)
    res = disp.dispatch(intent)
    assert res.ok
    # result fully scrubbed
    assert "SUPER-SECRET-KEY" not in str(res.data)
    assert "SUPER-SECRET-KEY" not in (res.resolved_command or "")
    assert PLACEHOLDER in res.resolved_command
    # audit log fully scrubbed
    blob = "".join(str(r.payload) for r in audit.records())
    assert "SUPER-SECRET-KEY" not in blob


def test_audit_chain_verifies_and_detects_tamper():
    audit = AuditLog(clock=lambda: NOW)
    disp = _dispatcher(audit=audit)
    disp.dispatch(_scan_intent())
    assert audit.verify()
    # tamper with a record's payload -> chain breaks
    audit.records()[0].payload["tool"] = "mutated"
    assert not audit.verify()


# --- helpers -------------------------------------------------------------

def _four_assets():
    reg = AssetRegistry()
    for h in ["h1", "h2", "h3", "h4"]:
        reg.register(Asset(h, "ssh-host", "t", "web-prod",
                           Authorization("s", "l", NOW - timedelta(days=1),
                                         NOW + timedelta(days=30))))
    return reg


# --- rate limiting & concurrency (integration) --------------------------

def _patch(pkg, targets=("web-prod-01",)):
    return Intent(tool="patch.apply", params={"host": "web-prod-01", "pkg": pkg},
                  targets=list(targets), action_class=ActionClass.PATCH_CANARY,
                  reason="r", source_ref="CVE-2026-1234")


def test_scans_are_never_rate_limited():
    # A limiter that would block any change must not touch read-only scans.
    disp = _dispatcher(rate_limiter=RateLimiter(per_host_changes_per_hour=0,
                                                fleet_concurrency=0))
    for _ in range(5):
        assert disp.dispatch(_scan_intent()).ok


def test_mutating_change_rate_limited_per_host():
    rl = RateLimiter(per_host_changes_per_hour=1)
    disp, approvals = _approved_dispatcher(rl)

    a = _patch("openssl")
    _approve(disp, approvals, a)
    assert disp.dispatch(a).ok                    # first change counts

    b = _patch("bash")
    _approve(disp, approvals, b)
    res = disp.dispatch(b)                         # second within the hour
    assert not res.ok and "rate limit" in res.summary


def test_fleet_concurrency_blocks_then_frees():
    rl = RateLimiter(fleet_concurrency=1)
    held, _ = rl.try_begin(["other-host"], NOW)   # occupy the only slot
    disp, approvals = _approved_dispatcher(rl)

    a = _patch("openssl")
    _approve(disp, approvals, a)
    assert not disp.dispatch(a).ok                # no slot -> blocked

    rl.end(held)                                  # free the slot
    assert disp.dispatch(a).ok


def test_concurrency_slot_released_after_success():
    backend = InMemoryRateBackend()
    disp, approvals = _approved_dispatcher(RateLimiter(backend, fleet_concurrency=1))
    a = _patch("openssl")
    _approve(disp, approvals, a)
    assert disp.dispatch(a).ok
    assert backend.current_concurrency() == 0     # released, not leaked


def test_concurrency_slot_released_on_execution_error():
    backend = InMemoryRateBackend()
    rl = RateLimiter(backend, fleet_concurrency=1)

    reg = ToolRegistry()

    def boom(params, *, resolve_secret):
        raise RuntimeError("kaboom")

    reg.register(ToolSpec("patch.apply", schema={}, executor=boom,
                          capability=ToolCapability.MUTATING))
    approvals = ApprovalGate()
    disp = Dispatcher(
        registry=reg, policy=PolicyEngine(POLICY_CONFIG), assets=_assets(),
        approvals=approvals, vault=Vault(FakeBackend({})),
        audit=AuditLog(clock=lambda: NOW), clock=lambda: NOW, rate_limiter=rl,
    )
    a = _patch("openssl")
    cs_id = disp.dispatch(a).data["change_set_id"]
    approvals.decide(cs_id, "lead", approve=True, now=NOW)
    res = disp.dispatch(a)
    assert not res.ok and "execution error" in res.summary
    assert backend.current_concurrency() == 0     # finally released the slot
