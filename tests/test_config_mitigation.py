"""Config drop-in mitigations: write a reviewed file into an allowlisted dir via
`sudo -n tee`, validate+reload, roll back on failure — and reach it through the
mitigate path."""

import os
from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_demo_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.ssh.catalog import CONFIG_ACTIONS, DropInWrite
from ai_defense.ssh.config_exec import ConfigExecutor
from ai_defense.ssh.executor import CommandOutput, SSHExecutor

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


# --- ConfigExecutor ------------------------------------------------------

def test_dropin_write_applies_with_tee_and_reload():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.sysctl_mptcp_off"], host="h", key="k", user="ubuntu")
    assert out.applied
    tee = next(c for c in tp.calls if c[0][:3] == ("sudo", "-n", "tee"))
    assert "net.mptcp.enabled = 0" in tee[1]                 # content fed on stdin
    assert any("sysctl" in " ".join(a) for a in _argvs(tp))  # reload/validate ran
    assert not any(a[:4] == ("sudo", "-n", "rm", "-f") for a in _argvs(tp))  # no rollback


def test_dropin_write_rolls_back_when_reload_fails():
    tp = _T(fail_on="sysctl -p")                             # the validate/reload fails
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.sysctl_mptcp_off"], host="h", key="k")
    assert not out.applied and "removed" in out.blocked_reason
    assert any(a[:4] == ("sudo", "-n", "rm", "-f") for a in _argvs(tp))  # rolled back


def test_dropin_remove():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.sysctl_mptcp_off.remove"], host="h", key="k")
    assert out.applied
    assert any(a[:4] == ("sudo", "-n", "rm", "-f") for a in _argvs(tp))


def test_dropin_refuses_non_allowlisted_path():
    out = ConfigExecutor(SSHExecutor(_T())).apply(
        DropInWrite("evil", "/etc/passwd", "x:0:0\n"), host="h", key="k")
    assert not out.applied and "allowlisted" in out.blocked_reason


# --- end to end through mitigate ----------------------------------------

def _host(asset_id="h") -> Asset:
    now = datetime.now(UTC)
    return Asset(asset_id, "ssh-host", "ops", "prod",
                 Authorization("s", "o", now - timedelta(minutes=1), now + timedelta(days=90)),
                 connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01",
                                           user="ubuntu"))


def test_engine_mitigate_applies_a_config_dropin():
    # MPTCP mitigation is a config drop-in loaded from the shipped folder.
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    eng.registry.register(_host("h"))
    pending = eng.mitigate("h", "MPTCP")
    assert not pending.ok and pending.data["approval_state"] == "pending"
    eng.approve(pending.data["change_set_id"])
    done = handle_call(eng, "mitigate", {"asset_id": "h", "cve": "MPTCP"})
    assert done["ok"] is True
    assert done["data"]["rollback"]["kind"] == "config_edit"
