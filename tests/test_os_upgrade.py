"""The strongly-gated OS_UPGRADE workflow: preflight gate, mandatory snapshot,
approval-gated upgrade+reboot, reconnect/health/re-scan, and HALT-with-restore-
point on failure. Workflow logic is tested with fakes; the approval gating is
tested end-to-end through the engine."""

from datetime import UTC, datetime, timedelta

from ai_defense.cloud.tools import SNAPSHOT_TOOL
from ai_defense.composition import build_demo_engine, build_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.scanner.scanner import HostFindings
from ai_defense.ssh.config_exec import ConfigExecutor
from ai_defense.ssh.executor import CommandOutput, SSHExecutor
from ai_defense.ssh.tools import OS_UPGRADE_TIMEOUT_S, OS_UPGRADE_TOOL, make_os_upgrade_tool
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


def _findings(version: str | None, *, reachable: bool = True,
              distro: str = "ubuntu", codename: str = "x") -> HostFindings:
    if not reachable:
        return HostFindings(asset_id="h", misconfigurations=["scan failed: TimeoutError"])
    osr = {"ID": distro, "VERSION_ID": version, "VERSION_CODENAME": codename} if version else {}
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
    # reconnect must observe the host go DOWN (reboot) then come back UP on target
    sc = _Scanner(_findings("18.04"), [_findings(None, reachable=False), _findings("20.04")])
    r = _wf(disp, sc).run("h")
    assert r.status == UPGRADED and r.reconnected and r.post_os == "20.04"
    assert r.snapshot_ids == ["snap-1"]
    assert [i.tool for i in disp.calls] == [SNAPSHOT_TOOL, OS_UPGRADE_TOOL]   # snapshot first
    up = next(i for i in disp.calls if i.tool == OS_UPGRADE_TOOL)
    assert up.action_class == ActionClass.OS_UPGRADE_CANARY
    assert up.params["snapshot_id"] == "snap-1" and up.params["target_version"] == "20.04"


def test_reconnect_but_wrong_version_halts_and_keeps_snapshot():
    disp = _Dispatcher(upgrade="ok")
    # went down and came back, but still on 18.04 (upgrade didn't take)
    sc = _Scanner(_findings("18.04"), [_findings(None, reachable=False), _findings("18.04")])
    r = _wf(disp, sc).run("h")
    assert r.status == HEALTH_FAILED_HALTED and r.reconnected
    assert r.snapshot_ids == ["snap-1"] and any("restore" in n.lower() for n in r.notes)


def test_never_went_down_is_not_accepted_as_rebooted():
    # a host that stays reachable on the target version the whole time (os-release
    # is rewritten before reboot) must NOT be read as a successful reboot.
    disp = _Dispatcher(upgrade="ok")
    sc = _Scanner(_findings("18.04"), [_findings("20.04"), _findings("20.04")])
    r = _wf(disp, sc).run("h")
    assert r.status == HEALTH_FAILED_HALTED and not r.reconnected


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


def test_debian_threads_distro_and_codenames_from_the_preflight():
    # distro/old_codename/new_codename must come from the release-table lookup
    # (via the preflight report), never be left for the tool to guess.
    disp = _Dispatcher(upgrade="ok")
    sc = _Scanner(_findings("10", distro="debian", codename="buster"),
                  [_findings(None, reachable=False),
                   _findings("11", distro="debian", codename="bullseye")])
    r = _wf(disp, sc).run("h")
    assert r.status == UPGRADED and r.post_os == "11"
    up = next(i for i in disp.calls if i.tool == OS_UPGRADE_TOOL)
    assert up.params["distro"] == "debian"
    assert up.params["old_codename"] == "buster"
    assert up.params["new_codename"] == "bullseye"


# --- end-to-end through the engine (real policy + approval gate) ---------

def _host(asset_id="up-h") -> Asset:
    now = datetime.now(UTC)
    return Asset(asset_id, "ssh-host", "ops", "prod",
                 Authorization("s", "o", now - timedelta(minutes=1), now + timedelta(days=90)),
                 connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01",
                                           user="ubuntu"))


def _fast_reconnect(eng):
    # the demo host never "goes down", so cap the reconnect poll so the test
    # doesn't wait out the real 30x10s; it will correctly halt (never rebooted).
    eng.os_workflow._attempts = 2
    eng.os_workflow._delay = 0
    eng.os_workflow._sleep = lambda _s: None


def test_engine_canary_needs_two_approvals_then_applies_and_halts_in_sim():
    eng = build_demo_engine()
    _fast_reconnect(eng)
    eng.registry.register(_host("up-h"))
    p = eng.os_upgrade("up-h")
    assert p.status == UPGRADE_PENDING and p.change_set_id and p.snapshot_ids   # snapshot taken

    eng.approve(p.change_set_id, "op1")
    mid = eng.os_upgrade("up-h")                             # engine reuses the stored snapshot
    assert mid.status == UPGRADE_PENDING                     # one approval isn't enough

    eng.approve(p.change_set_id, "op2")
    done = eng.os_upgrade("up-h")
    # upgrade applies; the demo host never goes down, so the reboot can't be
    # confirmed -> halt, with the mandatory snapshot retained as the restore point.
    assert done.upgrade.ok and done.status == HEALTH_FAILED_HALTED
    assert done.snapshot_ids == p.snapshot_ids


def test_engine_fleet_blocked_until_a_canary_is_healthy():
    eng = build_demo_engine()
    _fast_reconnect(eng)
    eng.registry.register(_host("fl-h"))
    g = eng.os_upgrade("fl-h", canary=False)
    assert g.status == UPGRADE_PENDING
    eng.approve(g.change_set_id, "op1")
    eng.approve(g.change_set_id, "op2")
    # approved, but the canary->fleet precondition is unmet -> still gated
    g2 = eng.os_upgrade("fl-h", canary=False)
    assert g2.status == UPGRADE_PENDING

    eng._os_canary_ok = True                                 # a canary came back healthy
    eng.os_upgrade("fl-h", canary=False)                     # marks the precondition
    g3 = eng.os_upgrade("fl-h", canary=False)
    assert g3.upgrade and g3.upgrade.ok                      # now clears and applies


# --- the os.release_upgrade tool: upgrade + reboot, long timeout ---------

class _UpgradeTransport:
    """exec stub keyed on argv: dry-run `-c`, apply `-f`, and reboot."""

    def __init__(self, *, dryrun_exit=0, upgrade_exit=0, reboot="ok"):
        self.dryrun_exit = dryrun_exit
        self.upgrade_exit = upgrade_exit
        self.reboot = reboot            # "ok" | "refused" | "drop" | "channel_closed"
        self.calls: list = []

    def run(self, host, argv, *, key, timeout, user="root", port=22, input=None):
        self.calls.append((tuple(argv), timeout))
        a = " ".join(argv)
        if "do-release-upgrade -c" in a:
            return CommandOutput(self.dryrun_exit, "", "")
        if "do-release-upgrade -f" in a:
            return CommandOutput(self.upgrade_exit, "upgrade log...", "")
        if "systemctl reboot" in a:
            if self.reboot == "drop":
                raise OSError("connection dropped by reboot")
            if self.reboot == "channel_closed":
                return CommandOutput(-1, "", "")     # paramiko recv_exit_status on close
            return CommandOutput(0 if self.reboot == "ok" else 1, "", "reboot refused")
        return CommandOutput(0, "", "")


def _os_tool(tp):
    spec = make_os_upgrade_tool(
        SSHExecutor(tp), lambda _a: ConnectionInfo(host="h", key_ref="k", user="ubuntu"))
    return spec.executor


def test_tool_happy_upgrade_then_reboot_uses_long_timeout():
    tp = _UpgradeTransport(reboot="ok")
    res = _os_tool(tp)({"asset_id": "h", "target_version": "20.04", "snapshot_id": "snap-1"},
                       resolve_secret=lambda _r: "KEY")
    assert res.ok and res.data["reboot_issued"] is True
    assert res.data["rollback"]["payload"]["snapshot_id"] == "snap-1"
    # the upgrade (and its -c dry-run) ran with the long timeout, not the default 60s
    up = next(t for (argv, t) in tp.calls if "do-release-upgrade" in " ".join(argv)
              and "-f" in argv)
    assert up == OS_UPGRADE_TIMEOUT_S


def test_tool_reboot_refused_is_not_reported_as_success():
    tp = _UpgradeTransport(reboot="refused")      # sudo refused, connection did NOT drop
    res = _os_tool(tp)({"asset_id": "h", "target_version": "20.04", "snapshot_id": "snap-1"},
                       resolve_secret=lambda _r: "KEY")
    assert not res.ok and "NOT rebooted" in res.summary
    assert res.data["reboot_issued"] is False and res.data["rollback"]["payload"]["snapshot_id"]


def test_tool_reboot_dropping_connection_is_success():
    tp = _UpgradeTransport(reboot="drop")         # reboot severs SSH -> expected success
    res = _os_tool(tp)({"asset_id": "h"}, resolve_secret=lambda _r: "KEY")
    assert res.ok and res.data["reboot_issued"] is True


def test_tool_reboot_channel_closed_is_success():
    # paramiko returns exit -1 (not an exception) when the reboot closes the
    # channel before a status arrives — that's a real reboot, not a failure.
    tp = _UpgradeTransport(reboot="channel_closed")
    res = _os_tool(tp)({"asset_id": "h"}, resolve_secret=lambda _r: "KEY")
    assert res.ok and res.data["reboot_issued"] is True


def test_tool_no_upgrade_available_aborts_before_changing_anything():
    tp = _UpgradeTransport(dryrun_exit=1)         # `do-release-upgrade -c` says none available
    res = _os_tool(tp)({"asset_id": "h"}, resolve_secret=lambda _r: "KEY")
    assert not res.ok and "not applied" in res.summary
    assert not any("-f" in argv for (argv, _t) in tp.calls)      # apply never ran
    assert not any("systemctl reboot" in " ".join(argv) for (argv, _t) in tp.calls)


def test_tool_upgrade_command_failure_does_not_reboot():
    tp = _UpgradeTransport(upgrade_exit=1)
    res = _os_tool(tp)({"asset_id": "h"}, resolve_secret=lambda _r: "KEY")
    assert not res.ok and "command failed" in res.summary
    assert not any("systemctl reboot" in " ".join(argv) for (argv, _t) in tp.calls)


# --- the os.release_upgrade tool: Debian path ----------------------------

class _DebianTransport:
    """exec stub for the Debian sequence: grep sources.list.d, cat/tee
    sources.list, apt-get update (validate), apt-get full-upgrade, reboot."""

    def __init__(self, *, sources="deb http://deb.debian.org/debian buster main\n",
                 sld_hit=False, apt_update_exit=0, upgrade_exit=0, reboot="ok"):
        self.sources = sources
        self.sld_hit = sld_hit
        self.apt_update_exit = apt_update_exit
        self.upgrade_exit = upgrade_exit
        self.reboot = reboot
        self.calls: list = []

    def run(self, host, argv, *, key, timeout, user="root", port=22, input=None):
        self.calls.append((tuple(argv), input, timeout))
        a = " ".join(argv)
        if argv[:2] == ["grep", "-rl"]:
            out = "/etc/apt/sources.list.d/extra.list" if self.sld_hit else ""
            return CommandOutput(0 if self.sld_hit else 1, out, "")
        if argv[:3] == ["sudo", "-n", "cat"]:
            return CommandOutput(0, self.sources, "")
        if argv[:3] == ["sudo", "-n", "tee"] and input is not None:
            self.sources = input
            return CommandOutput(0, input, "")
        if argv[:3] == ["sudo", "-n", "cp"]:
            return CommandOutput(0, "", "")
        if "apt-get update" in a:
            return CommandOutput(self.apt_update_exit, "", "" if self.apt_update_exit == 0
                                 else "404  Not Found")
        if "apt-get full-upgrade --simulate" in a:
            return CommandOutput(0, "", "")
        if "apt-get -y full-upgrade" in a:
            return CommandOutput(self.upgrade_exit, "upgraded", "")
        if "systemctl reboot" in a:
            if self.reboot == "drop":
                raise OSError("connection dropped by reboot")
            return CommandOutput(0 if self.reboot == "ok" else 1, "", "")
        return CommandOutput(0, "", "")


def _debian_tool(tp, *, wire_config=True):
    ce = ConfigExecutor(SSHExecutor(tp)) if wire_config else None
    spec = make_os_upgrade_tool(
        SSHExecutor(tp), lambda _a: ConnectionInfo(host="h", key_ref="k", user="root"),
        config_executor=ce)
    return spec.executor


_DEBIAN_PARAMS = {"asset_id": "h", "distro": "debian", "old_codename": "buster",
                  "new_codename": "bullseye", "target_version": "11", "snapshot_id": "snap-1"}


def test_debian_happy_path_swaps_sources_then_upgrades_and_reboots():
    tp = _DebianTransport()
    res = _debian_tool(tp)(_DEBIAN_PARAMS, resolve_secret=lambda _r: "KEY")
    assert res.ok and res.data["reboot_issued"] is True
    assert "bullseye" in tp.sources and "buster" not in tp.sources
    # the full-upgrade (and its --simulate dry-run) ran with the long timeout
    up_call = next(t for (argv, _i, t) in tp.calls
                   if "apt-get" in argv and "full-upgrade" in argv and "-y" in argv)
    assert up_call == OS_UPGRADE_TIMEOUT_S
    assert any("apt-get update" in " ".join(a) for (a, _i, _t) in tp.calls)   # swap validated


def test_debian_missing_codenames_refused():
    res = _debian_tool(_DebianTransport())(
        {"asset_id": "h", "distro": "debian"}, resolve_secret=lambda _r: "KEY")
    assert not res.ok and "missing codename info" in res.summary


def test_debian_without_config_executor_refused():
    res = _debian_tool(_DebianTransport(), wire_config=False)(
        _DEBIAN_PARAMS, resolve_secret=lambda _r: "KEY")
    assert not res.ok and "not wired" in res.summary


def test_debian_unsafe_codename_refused():
    res = _debian_tool(_DebianTransport())(
        {**_DEBIAN_PARAMS, "old_codename": "buster; rm -rf /"},
        resolve_secret=lambda _r: "KEY")
    assert not res.ok and "unsafe codename" in res.summary


def test_debian_stale_thirdparty_source_refused_before_any_change():
    tp = _DebianTransport(sld_hit=True)
    res = _debian_tool(tp)(_DEBIAN_PARAMS, resolve_secret=lambda _r: "KEY")
    assert not res.ok and "sources.list.d" in res.summary
    assert "buster" in tp.sources            # sources.list was never touched
    assert not any(c[0][:3] == ("sudo", "-n", "tee") for c in tp.calls)


def test_debian_swap_validate_failure_restores_and_refuses():
    tp = _DebianTransport(apt_update_exit=1)      # apt-get update (the swap's validate) fails
    res = _debian_tool(tp)(_DEBIAN_PARAMS, resolve_secret=lambda _r: "KEY")
    assert not res.ok and "sources.list rewrite failed" in res.summary
    assert "404  Not Found" in res.data["stderr"]      # apt's own error reaches the approver
    assert any(c[0][:3] == ("sudo", "-n", "cp") for c in tp.calls)   # backup/restore ran
    assert not any("full-upgrade" in " ".join(c[0]) for c in tp.calls)  # upgrade never ran


def test_debian_full_upgrade_failure_does_not_reboot():
    tp = _DebianTransport(upgrade_exit=1)
    res = _debian_tool(tp)(_DEBIAN_PARAMS, resolve_secret=lambda _r: "KEY")
    assert not res.ok and "full-upgrade command failed" in res.summary
    assert not any("systemctl reboot" in " ".join(c[0]) for c in tp.calls)
    assert "bullseye" in tp.sources     # sources.list stays swapped; a retry won't re-swap


def test_debian_reboot_refused_is_not_reported_as_success():
    tp = _DebianTransport(reboot="refused")
    res = _debian_tool(tp)(_DEBIAN_PARAMS, resolve_secret=lambda _r: "KEY")
    assert not res.ok and "NOT rebooted" in res.summary


def test_mcp_os_upgrade_pending_shape():
    eng = build_demo_engine()
    eng.registry.register(_host("mcp-h"))
    out = handle_call(eng, "os_upgrade", {"asset_id": "mcp-h"})
    assert out["status"] == "upgrade_pending" and out["ok"] is False
    assert out["change_set_id"] and out["target_version"] == "20.04"
    assert out["snapshot_ids"] and "approve" in out["next"]


# --- end-to-end through the engine: Debian host ---------------------------

class _DebianInspector:
    """Reports a static Debian 10 (buster) host — mirrors demo.py's DemoInspector
    but for the Debian path."""

    def collect(self, asset_id):
        return {"installed_packages": {}, "applied_patches": [], "misconfigurations": [],
                "os_release": {"ID": "debian", "VERSION_ID": "10",
                               "VERSION_CODENAME": "buster"}}

    def collect_upgrade_state(self, asset_id):
        return {"reboot_required": False, "disk_free_mb": 20480,
                "held_packages": [], "broken_packages_report": ""}


def test_engine_debian_canary_swaps_sources_and_upgrades_then_halts_in_sim():
    eng = build_engine(inspector=_DebianInspector(), transport=_DebianTransport())
    _fast_reconnect(eng)
    eng.registry.register(_host("deb-h"))

    p = eng.os_upgrade("deb-h")
    assert p.status == UPGRADE_PENDING and p.preflight.distro == "debian"
    assert p.preflight.target_version == "11" and p.preflight.target_codename == "bullseye"

    eng.approve(p.change_set_id, "op1")
    eng.approve(p.change_set_id, "op2")
    done = eng.os_upgrade("deb-h")
    # the mutating sequence (third-party check, sources swap, full-upgrade, reboot)
    # all ran and succeeded; the static inspector never reports the host "down", so
    # the reconnect confirmation can't complete -> halt, snapshot retained (same
    # fail-safe shape as the Ubuntu engine test).
    assert done.upgrade.ok and done.status == HEALTH_FAILED_HALTED
    assert done.snapshot_ids == p.snapshot_ids
