"""PersistentApprovalGate: durable, cross-process approvals."""

from datetime import UTC, datetime, timedelta

from ai_defense.approval.gate import (
    ApprovalRequest,
    ApprovalState,
    PersistentApprovalGate,
)
from ai_defense.db import ApprovalRepository, init_db

NOW = datetime(2026, 11, 3, tzinfo=UTC)


def _req(cs="cs_1", required=1, unlock=None, ttl_h=1):
    return ApprovalRequest(
        change_set_id=cs, resolved_commands=["patch.apply(openssl)"], blast_radius=1,
        source_ref="CVE-2026-1", requested_at=NOW, expires_at=NOW + timedelta(hours=ttl_h),
        approvals_required=required, unlock_after=unlock,
    )


def test_request_is_idempotent_and_durable():
    sf = init_db()
    gate = PersistentApprovalGate(ApprovalRepository(sf))
    gate.request(_req())
    gate.request(_req())                        # same change-set again -> no dup
    assert gate.state_for("cs_1", NOW) == ApprovalState.PENDING


def test_decision_survives_a_fresh_gate_instance():
    sf = init_db()
    ApprovalRepository(sf)  # ensure schema
    PersistentApprovalGate(ApprovalRepository(sf)).request(_req())

    # a different gate instance (think: another process) approves
    PersistentApprovalGate(ApprovalRepository(sf)).decide("cs_1", "lead", True, NOW)

    # yet another fresh instance sees it cleared
    gate3 = PersistentApprovalGate(ApprovalRepository(sf))
    assert gate3.state_for("cs_1", NOW) == ApprovalState.APPROVED
    assert gate3.is_cleared("cs_1", NOW)


def test_n_of_m_accumulates_across_instances():
    sf = init_db()
    PersistentApprovalGate(ApprovalRepository(sf)).request(_req(required=2))
    PersistentApprovalGate(ApprovalRepository(sf)).decide("cs_1", "lead-1", True, NOW)
    # still pending after one of two
    assert PersistentApprovalGate(ApprovalRepository(sf)).state_for("cs_1", NOW) \
        == ApprovalState.PENDING
    PersistentApprovalGate(ApprovalRepository(sf)).decide("cs_1", "lead-2", True, NOW)
    assert PersistentApprovalGate(ApprovalRepository(sf)).state_for("cs_1", NOW) \
        == ApprovalState.APPROVED


def test_canary_precondition_persists():
    sf = init_db()
    g = PersistentApprovalGate(ApprovalRepository(sf))
    g.request(_req(unlock="canary_health_ok"))
    g.decide("cs_1", "lead", True, NOW)
    assert not g.is_cleared("cs_1", NOW)        # approved but precondition unmet
    PersistentApprovalGate(ApprovalRepository(sf)).mark_precondition_met("cs_1")
    assert PersistentApprovalGate(ApprovalRepository(sf)).is_cleared("cs_1", NOW)


def test_expiry_persists():
    sf = init_db()
    PersistentApprovalGate(ApprovalRepository(sf)).request(_req(ttl_h=1))
    later = NOW + timedelta(hours=2)
    assert PersistentApprovalGate(ApprovalRepository(sf)).state_for("cs_1", later) \
        == ApprovalState.EXPIRED
    # persisted: a fresh instance at an earlier clock still sees EXPIRED (terminal)
    assert PersistentApprovalGate(ApprovalRepository(sf)).state_for("cs_1", NOW) \
        == ApprovalState.EXPIRED


def test_decide_unknown_change_set_raises():
    sf = init_db()
    import pytest
    with pytest.raises(KeyError):
        PersistentApprovalGate(ApprovalRepository(sf)).decide("nope", "x", True, NOW)


def test_engine_dispatcher_sees_externally_persisted_approval():
    # The payoff: an operator (separate gate instance / process) approves against
    # the shared DB, and the engine's dispatcher honours it on the next call.
    from ai_defense.composition import build_demo_engine
    from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo

    sf = init_db()
    eng = build_demo_engine(session_factory=sf)
    now = datetime.now(UTC)
    eng.registry.register(Asset(
        "vps-demo-01", "ssh-host", "ops", "prod",
        Authorization("sig", "op", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="198.51.100.20", key_ref="ssh-key/vps-demo-01"),
    ))
    item = next(it for it in eng.plan(eng.scan(["vps-demo-01"])) if it.intent)

    pending = eng.remediate(item, snapshot=False)
    assert pending.status == "patch_pending"
    cs_id = pending.patch.data["change_set_id"]

    # a DIFFERENT gate instance approves against the same DB
    PersistentApprovalGate(ApprovalRepository(sf)).decide(cs_id, "secops-lead", True)

    applied = eng.remediate(item, snapshot=False)
    assert applied.status == "patched"
    assert eng.audit_ok()
