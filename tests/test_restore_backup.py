"""Restoring an allowlisted file from the backup its last in-place edit left:
the read-only ``config.backup_diff`` preview and the approval-gated
``config.restore_backup`` (CLAUDE.md 6a — every primitive records a rollback)."""

from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.ssh.config_exec import ConfigExecutor
from ai_defense.ssh.executor import CommandOutput, SSHExecutor

SRC = "/etc/apt/sources.list"
SSHD = "/etc/ssh/sshd_config"
BUSTER = "deb http://deb.debian.org/debian buster main\n"
BULLSEYE = "deb http://deb.debian.org/debian bullseye main\n"


class _FS:
    """A tiny remote filesystem: `sudo -n cat|cp|tee` over a dict of files."""

    def __init__(self, files, fail_on=None):
        self.files = dict(files)
        self.fail_on = fail_on
        self.calls: list[tuple] = []

    def run(self, host, argv, *, key, timeout, user="root", port=22, input=None):
        self.calls.append(tuple(argv))
        if self.fail_on and self.fail_on in " ".join(argv):
            return CommandOutput(1, "", "rejected")
        cmd, args = argv[2], argv[3:]
        if cmd == "cat":
            if args[0] not in self.files:
                return CommandOutput(1, "", f"cat: {args[0]}: No such file or directory")
            return CommandOutput(0, self.files[args[0]], "")
        if cmd == "cp":
            self.files[args[1]] = self.files[args[0]]
            return CommandOutput(0, "", "")
        if cmd == "tee":
            self.files[args[0]] = input
            return CommandOutput(0, input, "")
        return CommandOutput(0, "", "")


def _ce(fs):
    return ConfigExecutor(SSHExecutor(fs))


def test_preview_shows_the_diff_and_changes_nothing():
    fs = _FS({SRC: BULLSEYE, SRC + ".ai-defense.bak": BUSTER})
    out = _ce(fs).backup_diff(SRC, host="h", key="k")
    assert out.applied and "-" + BULLSEYE in out.diff and "+" + BUSTER in out.diff
    assert fs.files[SRC] == BULLSEYE
    assert all(c[2] == "cat" for c in fs.calls)                  # reads only


def test_restore_puts_the_backup_back_and_keeps_the_replaced_file():
    fs = _FS({SRC: BULLSEYE, SRC + ".ai-defense.bak": BUSTER})
    out = _ce(fs).restore_backup(SRC, host="h", key="k")
    assert out.applied and out.diff
    assert fs.files[SRC] == BUSTER
    assert fs.files[SRC + ".ai-defense.pre-restore"] == BULLSEYE
    assert not any("apt-get" in " ".join(c) for c in fs.calls)  # sources.list: no validator


def test_restore_is_idempotent():
    fs = _FS({SRC: BUSTER, SRC + ".ai-defense.bak": BUSTER})
    out = _ce(fs).restore_backup(SRC, host="h", key="k")
    assert out.applied and out.diff == ""
    assert not any(c[2] == "cp" for c in fs.calls)


def test_missing_backup_is_refused_and_nothing_changes():
    fs = _FS({SRC: BULLSEYE})
    out = _ce(fs).restore_backup(SRC, host="h", key="k")
    assert not out.applied and "no backup" in out.blocked_reason
    assert fs.files == {SRC: BULLSEYE}


def test_path_off_the_allowlist_is_refused_without_reading_it():
    fs = _FS({"/etc/shadow": "x", "/etc/shadow.ai-defense.bak": "y"})
    for op in ("backup_diff", "restore_backup"):
        out = getattr(_ce(fs), op)("/etc/shadow", host="h", key="k")
        assert not out.applied and "allowlisted" in out.blocked_reason
    assert fs.calls == []


def test_failed_validation_puts_the_original_back():
    fs = _FS({SSHD: "Port 22\nX11Forwarding no\n", SSHD + ".ai-defense.bak": "Port 22\n"},
             fail_on="sshd -t")
    out = _ce(fs).restore_backup(SSHD, host="h", key="k")
    assert not out.applied and "original put back" in out.blocked_reason
    assert fs.files[SSHD] == "Port 22\nX11Forwarding no\n"
    assert not any("reload" in c for c in fs.calls)


def test_validated_restore_reloads():
    fs = _FS({SSHD: "Port 22\nX11Forwarding no\n", SSHD + ".ai-defense.bak": "Port 22\n"})
    out = _ce(fs).restore_backup(SSHD, host="h", key="k")
    assert out.applied and fs.files[SSHD] == "Port 22\n"
    argvs = fs.calls
    assert ("sudo", "-n", "sshd", "-t") in argvs
    assert ("sudo", "-n", "systemctl", "reload", "sshd") in argvs


# --- through the engine + MCP (real policy and approval gate) ------------

def _host(asset_id="deb-h") -> Asset:
    now = datetime.now(UTC)
    return Asset(asset_id, "ssh-host", "ops", "prod",
                 Authorization("s", "o", now - timedelta(minutes=1), now + timedelta(days=90)),
                 connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01",
                                           user="admin"))


def test_mcp_restore_previews_then_waits_for_approval_then_applies():
    fs = _FS({SRC: BULLSEYE, SRC + ".ai-defense.bak": BUSTER})
    eng = build_engine(transport=fs)
    eng.registry.register(_host())

    first = handle_call(eng, "restore_config_backup", {"asset_id": "deb-h", "path": SRC})
    assert "+" + BUSTER in first["preview_diff"]
    assert first["change_set_id"] and fs.files[SRC] == BULLSEYE      # nothing yet

    eng.approve(first["change_set_id"], "op1")
    done = handle_call(eng, "restore_config_backup", {"asset_id": "deb-h", "path": SRC})
    assert done["ok"] and fs.files[SRC] == BUSTER
    assert done["data"]["rollback"]["payload"]["saved_copy"] == SRC + ".ai-defense.pre-restore"

    # once it matches, a re-call is just the read-only preview: no new change set
    again = handle_call(eng, "restore_config_backup", {"asset_id": "deb-h", "path": SRC})
    assert again["ok"] and again["data"]["identical"] and "change_set_id" not in again


def test_mcp_restore_refuses_a_non_allowlisted_path_before_any_approval():
    fs = _FS({"/etc/shadow": "x", "/etc/shadow.ai-defense.bak": "y"})
    eng = build_engine(transport=fs)
    eng.registry.register(_host())
    out = handle_call(eng, "restore_config_backup", {"asset_id": "deb-h", "path": "/etc/shadow"})
    assert not out["ok"] and "change_set_id" not in out and out["preview_diff"] is None
    assert fs.calls == []
