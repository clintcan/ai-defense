"""Persistence layer tests: round-trips, durability, and audit-chain integrity.

Uses an in-memory SQLite kept alive by the engine (StaticPool) so separate
sessions and separate AuditLog/registry instances share the same data.
"""

from datetime import UTC, datetime, timedelta

from ai_defense.approval.gate import ApprovalGate, ApprovalRequest, ApprovalState
from ai_defense.audit.log import AuditLog
from ai_defense.db import (
    ApprovalRepository,
    AssetRepository,
    ScanFindingRepository,
    SecretRefRepository,
    SqlAuditStore,
    init_db,
)
from ai_defense.registry.assets import Asset, Authorization
from ai_defense.scanner.scanner import HostFindings

NOW = datetime(2026, 11, 3, tzinfo=UTC)


def _asset(asset_id="web-prod-01", expired=False):
    exp = NOW - timedelta(days=1) if expired else NOW + timedelta(days=30)
    return Asset(asset_id, "ssh-host", "team", "web-prod",
                 Authorization("sig-abc", "secops-lead", NOW - timedelta(days=1), exp))


# --- assets & authorization ---------------------------------------------

def test_asset_roundtrip_and_registry_hydration():
    sf = init_db()
    repo = AssetRepository(sf)
    repo.save(_asset())

    got = repo.get("web-prod-01")
    assert got is not None
    assert got.environment == "web-prod"
    assert got.authorization.granted_by == "secops-lead"

    # hydrate a registry from the DB and exercise the authz check
    reg = repo.load_registry()
    assert reg.require_authorized("web-prod-01", NOW).owner == "team"


def test_expired_authorization_persists_and_is_rejected():
    sf = init_db()
    repo = AssetRepository(sf)
    repo.save(_asset(expired=True))
    reg = repo.load_registry()
    import pytest
    with pytest.raises(PermissionError):
        reg.require_authorized("web-prod-01", NOW)


def test_latest_authorization_wins():
    sf = init_db()
    repo = AssetRepository(sf)
    repo.save(_asset())                      # grant #1
    newer = Asset("web-prod-01", "ssh-host", "team", "web-prod",
                  Authorization("sig-new", "ciso", NOW, NOW + timedelta(days=365)))
    repo.save(newer)                         # grant #2 (newer)
    assert repo.get("web-prod-01").authorization.granted_by == "ciso"


# --- secret refs (ciphertext only) --------------------------------------

def test_secret_ref_stores_ciphertext_only():
    sf = init_db()
    repo = SecretRefRepository(sf)
    repo.put("ssh-key/web", b"\x00ENCRYPTED\xff", "kms:key-1")
    ct, kid = repo.get_ciphertext("ssh-key/web")
    assert ct == b"\x00ENCRYPTED\xff"
    assert kid == "kms:key-1"


# --- approvals ----------------------------------------------------------

def _req(cs="cs_1", required=2, unlock=None):
    return ApprovalRequest(
        change_set_id=cs, resolved_commands=["patch.apply(openssl)"], blast_radius=1,
        source_ref="CVE-2026-1234", requested_at=NOW, expires_at=NOW + timedelta(hours=1),
        approvals_required=required, unlock_after=unlock,
    )


def test_approval_roundtrip_with_votes():
    sf = init_db()
    repo = ApprovalRepository(sf)
    req = _req()
    req.approvers = ["lead-1"]
    repo.save(req)
    # second distinct vote -> approved
    req.approvers = ["lead-1", "lead-2"]
    req.state = ApprovalState.APPROVED
    repo.save(req)

    loaded = repo.get("cs_1")
    assert loaded.approvals_required == 2
    assert set(loaded.approvers) == {"lead-1", "lead-2"}
    assert loaded.state == ApprovalState.APPROVED
    assert loaded.source_ref == "CVE-2026-1234"


def test_votes_are_deduped_on_resave():
    sf = init_db()
    repo = ApprovalRepository(sf)
    req = _req()
    req.approvers = ["lead-1"]
    repo.save(req)
    repo.save(req)                            # same approver again
    assert repo.get("cs_1").approvers == ["lead-1"]


def test_load_gate_reconstructs_decisions():
    sf = init_db()
    repo = ApprovalRepository(sf)
    req = _req(required=1)
    req.approvers = ["lead-1"]
    req.state = ApprovalState.APPROVED
    repo.save(req)

    gate: ApprovalGate = repo.load_gate()
    assert gate.state_for("cs_1", NOW) == ApprovalState.APPROVED
    assert gate.is_cleared("cs_1", NOW)


# --- scan findings ------------------------------------------------------

def test_scan_findings_latest():
    sf = init_db()
    repo = ScanFindingRepository(sf)
    repo.save(HostFindings("h1", {"openssl": "1.0"}, ["KB1"], []),
              scanned_at=NOW - timedelta(days=1))
    repo.save(HostFindings("h1", {"openssl": "3.0"}, ["KB1", "KB2"], ["ssh-root-login"]),
              scanned_at=NOW)
    latest = repo.latest("h1")
    assert latest.installed_packages["openssl"] == "3.0"
    assert "ssh-root-login" in latest.misconfigurations


# --- durable, tamper-evident audit log ----------------------------------

def test_audit_persists_and_verifies_across_instances():
    sf = init_db()
    store = SqlAuditStore(sf)

    log = AuditLog(clock=lambda: NOW, store=store)
    log.record("planner", "intent", {"tool": "scan.host", "cve": "CVE-2026-1234"})
    log.record("secops-lead", "approval", {"change_set_id": "cs_1", "state": "approved"})
    assert log.verify()

    # a brand-new AuditLog over the SAME store sees the persisted chain
    reloaded = AuditLog(clock=lambda: NOW, store=SqlAuditStore(sf))
    recs = reloaded.records()
    assert len(recs) == 2
    assert recs[0].payload["cve"] == "CVE-2026-1234"
    assert reloaded.verify()                  # hash chain intact after reload


def test_audit_chain_detects_persisted_tamper():
    sf = init_db()
    store = SqlAuditStore(sf)
    log = AuditLog(clock=lambda: NOW, store=store)
    log.record("planner", "intent", {"tool": "scan.host"})
    log.record("toolset", "result", {"tool": "scan.host", "ok": True})

    # tamper with a row directly in the database
    from sqlalchemy import select

    from ai_defense.db.models import AuditRow
    with sf() as s:
        row = s.execute(select(AuditRow).order_by(AuditRow.seq)).scalars().first()
        row.payload = {"tool": "mutated"}
        s.commit()

    assert not AuditLog(clock=lambda: NOW, store=SqlAuditStore(sf)).verify()


def test_dispatcher_writes_durable_audit_trail():
    # The whole enforcement stack over a SQL-backed audit store: a dispatch
    # persists its audit trail, readable and verifiable by a fresh instance.
    from ai_defense.approval.gate import ApprovalGate
    from ai_defense.toolset.dispatch import Dispatcher
    from ai_defense.toolset.intents import ActionClass, Intent, ToolResult
    from ai_defense.toolset.policy import PolicyEngine
    from ai_defense.toolset.registry import ToolCapability, ToolRegistry, ToolSpec
    from ai_defense.vault.vault import SecretsBackend, Vault

    class _B(SecretsBackend):
        def resolve(self, ref):
            return "x"

        def audit_access(self, ref, *, actor, reason):
            pass

    sf = init_db()
    AssetRepository(sf).save(_asset("h1"))
    reg = ToolRegistry()
    reg.register(ToolSpec(
        "scan.host", schema={},
        executor=lambda p, *, resolve_secret: ToolResult(ok=True, tool="scan.host", summary="ok"),
        capability=ToolCapability.READ_ONLY,
    ))
    disp = Dispatcher(
        registry=reg, policy=PolicyEngine({"autonomous_action_classes": ["scan"]}),
        assets=AssetRepository(sf).load_registry(), approvals=ApprovalGate(),
        vault=Vault(_B()), audit=AuditLog(clock=lambda: NOW, store=SqlAuditStore(sf)),
        clock=lambda: NOW,
    )
    res = disp.dispatch(Intent("scan.host", {}, ["h1"], ActionClass.SCAN, "inventory"))
    assert res.ok

    reloaded = AuditLog(clock=lambda: NOW, store=SqlAuditStore(sf))
    events = [r.event for r in reloaded.records()]
    assert events == ["intent", "policy", "result"]
    assert reloaded.verify()


def test_audit_hash_continuity_across_process_restart():
    # Appending via a fresh store instance must chain onto the persisted tail,
    # not restart from GENESIS.
    sf = init_db()
    AuditLog(clock=lambda: NOW, store=SqlAuditStore(sf)).record("a", "intent", {"n": 1})
    log2 = AuditLog(clock=lambda: NOW, store=SqlAuditStore(sf))
    log2.record("b", "result", {"n": 2})
    recs = log2.records()
    assert recs[1].prev_hash == recs[0].this_hash
    assert log2.verify()
