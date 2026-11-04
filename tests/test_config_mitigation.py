"""Config drop-in mitigations: write a reviewed file into an allowlisted dir via
`sudo -n tee`, validate+reload, roll back on failure — and reach it through the
mitigate path."""

import os
from datetime import UTC, datetime, timedelta

import pytest

from ai_defense.composition import build_demo_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.ssh.catalog import CONFIG_ACTIONS, AptSourcesCodenameSwap, DropInWrite
from ai_defense.ssh.config_edit import codename_present, ensure_block, remove_block, swap_codename
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


# --- in-place marker-block edits ----------------------------------------

def test_block_helpers_are_idempotent_and_reversible():
    base = "Port 22\nPermitRootLogin no\n"
    once = ensure_block(base, "m", "X11Forwarding no")
    assert "X11Forwarding no" in once and ">>> ai-defense:m" in once
    assert ensure_block(once, "m", "X11Forwarding no") == once        # idempotent
    replaced = ensure_block(once, "m", "X11Forwarding yes")
    assert "X11Forwarding yes" in replaced and "X11Forwarding no" not in replaced
    assert remove_block(replaced, "m") == base                        # clean reverse
    assert remove_block(base, "m") == base                            # no-op if absent


def test_swap_codename_helpers():
    sources = ("deb http://deb.debian.org/debian buster main\n"
               "deb http://security.debian.org/debian-security buster/updates main\n")
    assert codename_present(sources, "buster") and not codename_present(sources, "bullseye")
    swapped = swap_codename(sources, "buster", "bullseye")
    assert "buster" not in swapped and swapped.count("bullseye") == 2
    assert swap_codename(swapped, "buster", "bullseye") == swapped    # no-op: already swapped
    assert codename_present(swapped, "bullseye") and not codename_present(swapped, "buster")
    # whole-word only: "buster" must not match inside a longer identifier
    assert not codename_present("deb .../oldbusterthing main\n", "buster")


class _EditT:
    """Simulates a remote file: `cat` returns it, `tee` overwrites it."""

    def __init__(self, content="", fail_on=None):
        self.content = content
        self.calls: list[tuple] = []
        self.fail_on = fail_on

    def run(self, host, argv, *, key, timeout, user="root", port=22, input=None):
        self.calls.append((tuple(argv), input))
        if self.fail_on and self.fail_on in " ".join(argv):
            return CommandOutput(1, "", "bad")
        if argv[:3] == ["sudo", "-n", "cat"]:
            return CommandOutput(0, self.content, "")
        if argv[:3] == ["sudo", "-n", "tee"] and input is not None:
            self.content = input                       # the write
            return CommandOutput(0, input, "")
        return CommandOutput(0, "", "")


def test_inplace_edit_applies_block_backs_up_and_validates():
    tp = _EditT(content="Port 22\n")
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.sshd_disable_x11"], host="h", key="k")
    assert out.applied
    assert "X11Forwarding no" in tp.content and "ai-defense:sshd-x11" in tp.content
    assert out.diff and "X11Forwarding no" in out.diff
    argvs = [c[0] for c in tp.calls]
    assert ("sudo", "-n", "cp", "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.ai-defense.bak") in argvs           # backed up
    assert ("sudo", "-n", "sshd", "-t") in argvs                      # validated


def test_inplace_edit_is_idempotent():
    tp = _EditT(content="Port 22\n")
    ce = ConfigExecutor(SSHExecutor(tp))
    ce.apply(CONFIG_ACTIONS["config.sshd_disable_x11"], host="h", key="k")
    tp.calls.clear()
    out = ce.apply(CONFIG_ACTIONS["config.sshd_disable_x11"], host="h", key="k")
    assert out.applied and out.diff == ""                            # no change
    assert not any(a[0][:3] == ("sudo", "-n", "tee") for a in tp.calls)  # no re-write


def test_inplace_edit_restores_from_backup_on_validation_failure():
    tp = _EditT(content="Port 22\n", fail_on="sshd -t")
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.sshd_disable_x11"], host="h", key="k")
    assert not out.applied and "restored" in out.blocked_reason
    argvs = [c[0] for c in tp.calls]
    assert ("sudo", "-n", "cp", "/etc/ssh/sshd_config.ai-defense.bak",
            "/etc/ssh/sshd_config") in argvs                          # rolled back


def test_inplace_edit_remove_reverses_the_block():
    tp = _EditT(content="Port 22\n")
    ce = ConfigExecutor(SSHExecutor(tp))
    ce.apply(CONFIG_ACTIONS["config.sshd_disable_x11"], host="h", key="k")
    assert "X11Forwarding no" in tp.content
    ce.apply(CONFIG_ACTIONS["config.sshd_disable_x11.remove"], host="h", key="k")
    assert "X11Forwarding no" not in tp.content and "ai-defense:sshd-x11" not in tp.content


# --- Debian apt-sources codename swap (the OS_UPGRADE primitive) --------

_SWAP = AptSourcesCodenameSwap(
    "debian.swap", "/etc/apt/sources.list", "buster", "bullseye",
    validate=("sudo", "-n", "apt-get", "update"))


def test_codename_swap_applies_backs_up_and_validates():
    tp = _EditT(content="deb http://deb.debian.org/debian buster main\n")
    out = ConfigExecutor(SSHExecutor(tp)).apply(_SWAP, host="h", key="k")
    assert out.applied and "bullseye" in tp.content and "buster" not in tp.content
    argvs = [c[0] for c in tp.calls]
    assert ("sudo", "-n", "cp", "/etc/apt/sources.list",
            "/etc/apt/sources.list.ai-defense.bak") in argvs           # backed up
    assert ("sudo", "-n", "apt-get", "update") in argvs                # validated


def test_codename_swap_is_idempotent_on_retry():
    tp = _EditT(content="deb http://deb.debian.org/debian bullseye main\n")  # already swapped
    out = ConfigExecutor(SSHExecutor(tp)).apply(_SWAP, host="h", key="k")
    assert out.applied and out.diff == ""
    assert not any(c[0][:3] == ("sudo", "-n", "tee") for c in tp.calls)      # no re-write


def test_codename_swap_refuses_ambiguous_sources_file():
    # neither the old nor the new codename appears -- e.g. a symbolic stable/
    # oldstable sources.list. Fail safe rather than guess (CLAUDE.md #7).
    tp = _EditT(content="deb http://deb.debian.org/debian stable main\n")
    out = ConfigExecutor(SSHExecutor(tp)).apply(_SWAP, host="h", key="k")
    assert not out.applied and "neither" in out.blocked_reason
    assert not any(c[0][:3] == ("sudo", "-n", "tee") for c in tp.calls)


def test_codename_swap_restores_from_backup_on_validate_failure():
    tp = _EditT(content="deb http://deb.debian.org/debian buster main\n",
               fail_on="apt-get update")
    out = ConfigExecutor(SSHExecutor(tp)).apply(_SWAP, host="h", key="k")
    assert not out.applied and "restored" in out.blocked_reason
    argvs = [c[0] for c in tp.calls]
    assert ("sudo", "-n", "cp", "/etc/apt/sources.list.ai-defense.bak",
            "/etc/apt/sources.list") in argvs                          # rolled back


def test_codename_swap_rejects_unsafe_codename_at_construction():
    with pytest.raises(ValueError, match="unsafe codename"):
        AptSourcesCodenameSwap("x", "/etc/apt/sources.list", "buster && rm -rf /", "bullseye")


def test_list_mitigations_reports_loaded_set_and_kinds():
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    rows = handle_call(eng, "list_mitigations", {})["mitigations"]
    by_id = {r["mitigation_id"]: r for r in rows}
    # the shipped set, each tagged with the right action kind
    assert by_id["pwnkit-pkexec-suid"]["kind"] == "command"
    assert by_id["sack-panic-disable-tcp-sack"]["kind"] == "command"
    assert by_id["mptcp-disable"]["kind"] == "config-dropin"
    assert by_id["sshd-disable-x11"]["kind"] == "config-edit"
    # SACK entry reports all three CVEs and cites an advisory
    assert by_id["sack-panic-disable-tcp-sack"]["cves"] == \
        ["CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479"]
    assert "CVE-2019-11477" in by_id["sack-panic-disable-tcp-sack"]["source_ref"]


def test_list_mitigations_builtin_only():
    eng = build_demo_engine()                        # no folder
    rows = eng.list_mitigations()
    assert [r["mitigation_id"] for r in rows] == ["pwnkit-pkexec-suid"]


def test_engine_mitigate_applies_inplace_edit():
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    eng.registry.register(_host("h2"))
    p = eng.mitigate("h2", "SSHD-X11-FORWARDING")
    assert p.data["approval_state"] == "pending"
    eng.approve(p.data["change_set_id"])
    out = handle_call(eng, "mitigate", {"asset_id": "h2", "cve": "SSHD-X11-FORWARDING"})
    assert out["ok"] is True and out["data"].get("diff")


# --- drop-in: validate (nginx -t) before reload -------------------------

def test_dropin_validates_before_reload_and_rolls_back_on_validate_failure():
    # nginx HTTP/2 Rapid Reset drop-in: `nginx -t` runs before the reload, and a
    # validation failure deletes the drop-in (clean rollback) so nothing lingers.
    tp = _T(fail_on="nginx -t")
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.nginx_http2_rapidreset"], host="h", key="k")
    assert not out.applied and "removed" in out.blocked_reason
    argvs = _argvs(tp)
    assert any(a[:4] == ("sudo", "-n", "nginx", "-t") for a in argvs)       # validated
    assert not any("systemctl" in " ".join(a) for a in argvs)              # never reloaded
    assert any(a[:4] == ("sudo", "-n", "rm", "-f") for a in argvs)          # rolled back


def test_dropin_validate_then_reload_on_success():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.nginx_http2_rapidreset"], host="h", key="k", user="ubuntu")
    assert out.applied
    tee = next(c for c in tp.calls if c[0][:3] == ("sudo", "-n", "tee"))
    assert "http2_max_concurrent_streams 128" in tee[1]
    argvs = _argvs(tp)
    assert any(a[:4] == ("sudo", "-n", "nginx", "-t") for a in argvs)       # validated, then
    assert any(a[:5] == ("sudo", "-n", "systemctl", "reload", "nginx") for a in argvs)
    assert not any(a[:4] == ("sudo", "-n", "rm", "-f") for a in argvs)      # no rollback


# --- revert_mitigation: run the recorded rollback action ----------------

def test_engine_revert_mitigation_reverses_a_config_dropin():
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    eng.registry.register(_host("hr"))
    pending = eng.revert_mitigation("hr", "MPTCP")
    assert not pending.ok and pending.data["approval_state"] == "pending"
    eng.approve(pending.data["change_set_id"])
    done = handle_call(eng, "revert_mitigation", {"asset_id": "hr", "cve": "MPTCP"})
    assert done["ok"] is True
    assert done["data"]["reverse"] is True
    # the reverse ran the .remove action (a delete) and its undo is to re-apply
    assert done["data"]["rollback"]["payload"]["rollback_template"] == "config.sysctl_mptcp_off"


def test_php_upload_progress_dropin_writes_safe_setting_and_validates():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.php_disable_upload_progress"], host="h", key="k", user="ubuntu")
    assert out.applied
    tee = next(c for c in tp.calls if c[0][:3] == ("sudo", "-n", "tee"))
    assert "session.upload_progress.enabled = Off" in tee[1]
    argvs = _argvs(tp)
    assert any(a[:4] == ("sudo", "-n", "php-fpm8.1", "-t") for a in argvs)      # validated
    assert any(a[:5] == ("sudo", "-n", "systemctl", "reload", "php8.1-fpm") for a in argvs)


def test_php_upload_progress_bitnami_dropin_writes_and_restarts_via_ctlscript():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.php_disable_upload_progress_bitnami"],
        host="h", key="k", user="bitnami")
    assert out.applied
    tee = next(c for c in tp.calls if c[0][:3] == ("sudo", "-n", "tee"))
    assert tee[0][3] == "/opt/bitnami/php/etc/conf.d/99-ai-defense-hardening.ini"
    assert "session.upload_progress.enabled = Off" in tee[1]
    argvs = _argvs(tp)
    assert any(a[:3] == ("sudo", "-n", "/opt/bitnami/php/bin/php") for a in argvs)
    assert any(a[:4] == ("sudo", "-n", "/opt/bitnami/ctlscript.sh", "restart")
              for a in argvs)


def test_php_upload_progress_bitnami_reverse_removes_dropin():
    tp = _T()
    out = ConfigExecutor(SSHExecutor(tp)).apply(
        CONFIG_ACTIONS["config.php_disable_upload_progress_bitnami.remove"],
        host="h", key="k")
    assert out.applied
    assert any(a[:4] == ("sudo", "-n", "rm", "-f") for a in _argvs(tp))


def test_engine_mitigate_and_revert_php_bitnami():
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    eng.registry.register(_host("hpb"))
    cve = "PHP-SESSION-UPLOAD-PROGRESS-BITNAMI"
    p = eng.mitigate("hpb", cve)
    assert p.data["approval_state"] == "pending"
    eng.approve(p.data["change_set_id"])
    done = handle_call(eng, "mitigate", {"asset_id": "hpb", "cve": cve})
    assert done["ok"] is True
    r = eng.revert_mitigation("hpb", cve)
    assert r.data["approval_state"] == "pending"
    eng.approve(r.data["change_set_id"])
    reverted = handle_call(eng, "revert_mitigation", {"asset_id": "hpb", "cve": cve})
    assert reverted["ok"] is True and reverted["data"]["reverse"] is True


def test_engine_mitigate_and_revert_php_upload_progress():
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    eng.registry.register(_host("hp"))
    cve = "PHP-SESSION-UPLOAD-PROGRESS"
    p = eng.mitigate("hp", cve)
    assert p.data["approval_state"] == "pending"
    eng.approve(p.data["change_set_id"])
    assert handle_call(eng, "mitigate", {"asset_id": "hp", "cve": cve})["ok"] is True
    r = eng.revert_mitigation("hp", cve)
    assert r.data["approval_state"] == "pending"
    eng.approve(r.data["change_set_id"])
    done = handle_call(eng, "revert_mitigation", {"asset_id": "hp", "cve": cve})
    assert done["ok"] is True and done["data"]["reverse"] is True


def test_revert_is_a_distinct_approval_from_apply():
    # reverse=True changes the change-set id, so reverting needs its own approval —
    # approving the apply does not silently also authorize the revert.
    eng = build_demo_engine(mitigations_dir=_MITIGATIONS_DIR)
    eng.registry.register(_host("hd"))
    apply_cs = eng.mitigate("hd", "MPTCP").data["change_set_id"]
    revert_cs = eng.revert_mitigation("hd", "MPTCP").data["change_set_id"]
    assert apply_cs != revert_cs
