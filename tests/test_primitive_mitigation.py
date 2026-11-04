"""Kernel-module and service managed primitives: reviewed, allowlisted actions
applied through the same approval-gated mitigate/revert path as config edits."""

import os
from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_demo_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.ssh.catalog import MODULE_ACTIONS, SERVICE_ACTIONS, ModuleBlacklist
from ai_defense.ssh.catalog.services import ServiceStateChange
from ai_defense.ssh.config_exec import ConfigExecutor
from ai_defense.ssh.executor import CommandOutput, SSHExecutor
from ai_defense.ssh.hardening import ServiceAction

_MITIGATIONS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "mitigations")


class _T:
    """Records (argv, stdin); fails any command whose joined argv contains fail_on."""

    def __init__(self, fail_on: str | None = None):
        self.calls: list[tuple] = []
        self.fail_on = fail_on

    def run(self, host, argv, *, key, timeout, user="root", port=22, input=None):
        self.calls.append((tuple(argv), input))
        bad = self.fail_on is not None and self.fail_on in " ".join(argv)
        return CommandOutput(1 if bad else 0, "", "boom" if bad else "")


def _argvs(tp):
    return [c[0] for c in tp.calls]


def _host(asset_id="h") -> Asset:
    now = datetime.now(UTC)
    return Asset(asset_id, "ssh-host", "ops", "prod",
                 Authorization("s", "o", now - timedelta(minutes=1), now + timedelta(days=90)),
                 connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01",
                                           user="ubuntu"))


# --- kernel modules ------------------------------------------------------

def test_module_blacklist_writes_dropin_and_unloads():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        MODULE_ACTIONS["module.blacklist_dccp"], host="h", key="k", user="ubuntu")
    assert out.applied
    tee = next(c for c in tp.calls if c[0][:3] == ("sudo", "-n", "tee"))
    assert tee[0][3] == "/etc/modprobe.d/ai-defense-blacklist-dccp.conf"
    assert "blacklist dccp" in tee[1] and "install dccp /bin/true" in tee[1]
    assert ("sudo", "-n", "modprobe", "-r", "dccp") in _argvs(tp)


def test_module_blacklist_persists_even_if_unload_fails():
    tp = _T(fail_on="modprobe -r")              # module in use — can't unload now
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        MODULE_ACTIONS["module.blacklist_dccp"], host="h", key="k")
    assert out.applied                          # drop-in still written (blocks at boot)
    assert out.diff and "deferred" in out.diff


def test_module_unblacklist_removes_dropin():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        MODULE_ACTIONS["module.unblacklist_dccp"], host="h", key="k")
    assert out.applied
    assert ("sudo", "-n", "rm", "-f",
            "/etc/modprobe.d/ai-defense-blacklist-dccp.conf") in _argvs(tp)


def test_module_executor_refuses_non_allowlisted_module():
    out = ConfigExecutor(SSHExecutor(_T())).apply(
        ModuleBlacklist("module.blacklist_evil", "evil_mod"), host="h", key="k")
    assert not out.applied and "allowlist" in out.blocked_reason


def test_engine_mitigate_and_revert_kernel_module():
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    eng.registry.register(_host("hm"))
    cve = "CVE-2017-6074"
    p = eng.mitigate("hm", cve)
    assert p.data["approval_state"] == "pending"
    eng.approve(p.data["change_set_id"])
    done = handle_call(eng, "mitigate", {"asset_id": "hm", "cve": cve})
    assert done["ok"] is True and done["data"]["rollback"]["kind"] == "kernel_module"
    r = eng.revert_mitigation("hm", cve)
    eng.approve(r.data["change_set_id"])
    assert handle_call(eng, "revert_mitigation", {"asset_id": "hm", "cve": cve})["ok"] is True


# --- services ------------------------------------------------------------

def test_service_disable_runs_systemctl():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        SERVICE_ACTIONS["service.disable_rpcbind"], host="h", key="k", user="ubuntu")
    assert out.applied
    assert ("sudo", "-n", "systemctl", "disable", "--now", "rpcbind") in _argvs(tp)


def test_service_reverse_enables():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        SERVICE_ACTIONS["service.disable_rpcbind.reverse"], host="h", key="k")
    assert out.applied
    assert ("sudo", "-n", "systemctl", "enable", "--now", "rpcbind") in _argvs(tp)


def test_service_executor_refuses_protected_unit():
    # even if an action somehow named a protected unit, the executor refuses it.
    out = ConfigExecutor(SSHExecutor(_T())).apply(
        ServiceStateChange("service.disable_sshd", "sshd", ServiceAction.DISABLE),
        host="h", key="k")
    assert not out.applied and "protected unit" in out.blocked_reason


def test_catalog_refuses_shipping_a_protected_disable():
    # the services module guards at import; assert no shipped action disables a
    # protected unit.
    for a in SERVICE_ACTIONS.values():
        assert not a.is_blocked()


def test_engine_mitigate_and_revert_service():
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    eng.registry.register(_host("hs"))
    cve = "CVE-2017-8779"
    p = eng.mitigate("hs", cve)
    eng.approve(p.data["change_set_id"])
    done = handle_call(eng, "mitigate", {"asset_id": "hs", "cve": cve})
    assert done["ok"] is True and done["data"]["rollback"]["kind"] == "service"
    r = eng.revert_mitigation("hs", cve)
    eng.approve(r.data["change_set_id"])
    assert handle_call(eng, "revert_mitigation", {"asset_id": "hs", "cve": cve})["ok"] is True


def test_list_mitigations_tags_module_and_service_kinds():
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    rows = {r["mitigation_id"]: r for r in eng.list_mitigations()}
    assert rows["disable-dccp-module"]["kind"] == "kernel-module"
    assert rows["disable-rpcbind"]["kind"] == "service"
