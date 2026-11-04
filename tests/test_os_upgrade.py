"""The strongly-gated OS_UPGRADE workflow: preflight gate, mandatory snapshot,
approval-gated upgrade+reboot, reconnect/health/re-scan, and HALT-with-restore-
point on failure. Workflow logic is tested with fakes; the approval gating is
tested end-to-end through the engine."""

from datetime import UTC, datetime, timedelta

from ai_defense.cloud.tools import SNAPSHOT_TOOL
from ai_defense.composition import build_demo_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.scanner.scanner import HostFindings
from ai_defense.ssh.tools import OS_UPGRADE_TOOL
from ai_defense.toolset.intents import ActionClass, ToolResult
from ai_defense.upgrade.preflight import OsUpgradePreflight
from ai_defense.upgrade.workflow import (
    HEALTH_FAILED_HALTED,
    PREFLIGHT_BLOCKED,
    SNAPSHOT_FAILED,
    UPGRADE_PENDING,
    UPGRADED,
    OsUpgradeWorkflow,
)

_READY_STATE = {"reboot_required": False, "disk_free_mb": 20480,
                "held_packages": [], "broken_packages_report": ""}


def _findings(version: str | None, *, reachable: bool = True) -> HostFindings:
    if not reachable:
        return HostFindings(asset_id="h", misconfigurations=["scan failed: TimeoutError"])
    osr = {"ID": "ubuntu", "VERSION_ID": version, "VERSION_CODENAME": "x"} if version else {}
    return HostFindings(asset_id="h", os_release=osr, system_state=_READY_STATE)


class _Scanner:
    """Fake scanner: a fixed preflight finding, and a scripted sequence of
    reconnect findings returned on successive scan_host() calls."""

    def __init__(self, preflight: HostFindings, reconnect: list[HostFindings]):
        self._pf = preflight
        self._seq = reconnect
        self.i = 0

    def scan_host_for_upgrade(self, asset_id): return self._pf

    def scan_host(self, asset_id):
        f = self._seq[min(self.i, len(self._seq) - 1)]
        self.i += 1
        return f


class _Dispatcher:
    def __init__(self, *, snapshot_ok=True, upgrade="ok"):
        self.snapshot_ok = snapshot_ok
        self.upgrade = upgrade
        self.calls: list = []

    def dispatch(self, intent):
        self.calls.append(intent)
        if intent.tool == SNAPSHOT_TOOL:
            return (ToolResult(ok=True, tool=SNAPSHOT_TOOL, summary="snap",
                               data={"snapshot_ids": ["snap-1"]}) if self.snapshot_ok
                    else ToolResult(ok=False, tool=SNAPSHOT_TOOL, summary="snapshot failed"))
        if intent.tool == OS_UPGRADE_TOOL:
            if self.upgrade == "ok":
                return ToolResult(ok=True, tool=OS_UPGRADE_TOOL, summary="upgraded; reboot issued",
                                  data={"asset_id": intent.params["asset_id"],
                                        "reboot_issued": True})
            if self.upgrade == "pending":
                return ToolResult(ok=False, tool=OS_UPGRADE_TOOL, summary="pending",
                                  data={"approval_state": "pending", "change_set_id": "cs-os-1"})
            return ToolResult(ok=False, tool=OS_UPGRADE_TOOL, summary="blocked", data={})
        return ToolResult(ok=False, tool=intent.tool, summary="unexpected")


def _wf(disp, scanner):
    return OsUpgradeWorkflow(disp, scanner, OsUpgradePreflight(),
                             credential_ref_for=lambda _a: "cred",
                             reconnect_attempts=2, reconnect_delay_s=0, sleep=lambda _s: None)


# --- workflow state machine ---------------------------------------------

def test_happy_path_upgraded_snapshots_first_under_canary_class():
    disp = _Dispatcher(upgrade="ok")
    r = _wf(disp, _Scanner(_findings("18.04"), [_findings("20.04")])).run("h")
    assert r.status == UPGRADED and r.reconnected and r.post_os == "20.04"
    assert r.snapshot_ids == ["snap-1"]
    assert [i.tool for i in disp.calls] == [SNAPSHOT_TOOL, OS_UPGRADE_TOOL]   # snapshot first
    up = next(i for i in disp.calls if i.tool == OS_UPGRADE_TOOL)
    assert up.action_class == ActionClass.OS_UPGRADE_CANARY
    assert up.params["snapshot_id"] == "snap-1" and up.params["target_version"] == "20.04"


def test_reconnect_but_wrong_version_halts_and_keeps_snapshot():
    disp = _Dispatcher(upgrade="ok")
    r = _wf(disp, _Scanner(_findings("18.04"), [_findings("18.04")])).run("h")  # still 18.04
    assert r.status == HEALTH_FAILED_HALTED and r.reconnected
    assert r.snapshot_ids == ["snap-1"] and any("restore" in n.lower() for n in r.notes)


def test_no_reconnect_halts():
    disp = _Dispatcher(upgrade="ok")
    sc = _Scanner(_findings("18.04"), [_findings(None, reachable=False)])   # never comes back
    r = _wf(disp, sc).run("h")
    assert r.status == HEALTH_FAILED_HALTED and not r.reconnected
    assert sc.i == 2                                      # polled reconnect_attempts times


def test_snapshot_failure_aborts_before_upgrade():
    disp = _Dispatcher(snapshot_ok=False)
    r = _wf(disp, _Scanner(_findings("18.04"), [_findings("20.04")])).run("h")
    assert r.status == SNAPSHOT_FAILED
    assert [i.tool for i in disp.calls] == [SNAPSHOT_TOOL]   # upgrade never dispatched


def test_preflight_not_ready_dispatches_nothing():
    disp = _Dispatcher()
    r = _wf(disp, _Scanner(_findings("24.04"), [_findings("24.04")])).run("h")  # newest -> CURRENT
    assert r.status == PREFLIGHT_BLOCKED and disp.calls == []


def test_pending_returns_change_set_and_retained_snapshot():
    disp = _Dispatcher(upgrade="pending")
    r = _wf(disp, _Scanner(_findings("18.04"), [_findings("20.04")])).run("h")
    assert r.status == UPGRADE_PENDING and r.change_set_id == "cs-os-1"
    assert r.snapshot_ids == ["snap-1"]


def test_existing_snapshot_skips_resnapshot():
    disp = _Dispatcher(upgrade="ok")
    r = _wf(disp, _Scanner(_findings("18.04"), [_findings("20.04")])).run(
        "h", existing_snapshot_ids=["snap-prev"])
    assert [i.tool for i in disp.calls] == [OS_UPGRADE_TOOL]   # no snapshot dispatch
    assert r.snapshot_ids == ["snap-prev"]


def test_fleet_uses_fleet_action_class():
    disp = _Dispatcher(upgrade="pending")
    _wf(disp, _Scanner(_findings("18.04"), [_findings("20.04")])).run("h", canary=False)
    up = next(i for i in disp.calls if i.tool == OS_UPGRADE_TOOL)
    assert up.action_class == ActionClass.OS_UPGRADE_FLEET


# --- end-to-end through the engine (real policy + approval gate) ---------

def _host(asset_id="up-h") -> Asset:
    now = datetime.now(UTC)
    return Asset(asset_id, "ssh-host", "ops", "prod",
                 Authorization("s", "o", now - timedelta(minutes=1), now + timedelta(days=90)),
                 connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01",
                                           user="ubuntu"))


def test_engine_canary_needs_two_approvals_then_applies_and_halts_in_sim():
    eng = build_demo_engine()
    eng.registry.register(_host("up-h"))
    p = eng.os_upgrade("up-h")
    assert p.status == UPGRADE_PENDING and p.change_set_id and p.snapshot_ids   # snapshot taken

    eng.approve(p.change_set_id, "op1")
    mid = eng.os_upgrade("up-h", existing_snapshot_ids=p.snapshot_ids)
    assert mid.status == UPGRADE_PENDING                     # one approval isn't enough

    eng.approve(p.change_set_id, "op2")
    done = eng.os_upgrade("up-h", existing_snapshot_ids=p.snapshot_ids)
    # upgrade applies; the demo host still reports 18.04, so health halts and the
    # mandatory snapshot is retained as the restore point.
    assert done.upgrade.ok and done.status == HEALTH_FAILED_HALTED
    assert done.snapshot_ids == p.snapshot_ids


def test_engine_fleet_blocked_until_a_canary_is_healthy():
    eng = build_demo_engine()
    eng.registry.register(_host("fl-h"))
    g = eng.os_upgrade("fl-h", canary=False)
    assert g.status == UPGRADE_PENDING
    eng.approve(g.change_set_id, "op1")
    eng.approve(g.change_set_id, "op2")
    # approved, but the canary->fleet precondition is unmet -> still gated
    g2 = eng.os_upgrade("fl-h", canary=False, existing_snapshot_ids=g.snapshot_ids)
    assert g2.status == UPGRADE_PENDING

    eng._os_canary_ok = True                                 # a canary came back healthy
    eng.os_upgrade("fl-h", canary=False, existing_snapshot_ids=g.snapshot_ids)  # marks precondition
    g3 = eng.os_upgrade("fl-h", canary=False, existing_snapshot_ids=g.snapshot_ids)
    assert g3.upgrade and g3.upgrade.ok                      # now clears and applies


def test_mcp_os_upgrade_pending_shape():
    eng = build_demo_engine()
    eng.registry.register(_host("mcp-h"))
    out = handle_call(eng, "os_upgrade", {"asset_id": "mcp-h"})
    assert out["status"] == "upgrade_pending" and out["ok"] is False
    assert out["change_set_id"] and out["target_version"] == "20.04"
    assert out["snapshot_ids"] and "approve" in out["next"]
