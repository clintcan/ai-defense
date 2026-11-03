"""Real SSH backends: file/env vault, SSH host inspector, paramiko transport.

The vault and inspector are tested directly; the paramiko transport is tested by
injecting a fake ``paramiko`` module (no real SSH server/network)."""

import sys
import types

import pytest

from ai_defense.registry.assets import ConnectionInfo
from ai_defense.scanner.ssh_inspector import SSHHostInspector, _parse_dpkg
from ai_defense.ssh.executor import CommandOutput
from ai_defense.vault.backends import EnvVaultBackend, FileVaultBackend

# --- file vault ---------------------------------------------------------

def test_file_vault_reads_key(tmp_path):
    (tmp_path / "ssh-key").mkdir()
    (tmp_path / "ssh-key" / "vps-01").write_text("PRIVATE-KEY-DATA")
    vb = FileVaultBackend(tmp_path)
    assert vb.resolve("ssh-key/vps-01") == "PRIVATE-KEY-DATA"


def test_file_vault_missing_raises(tmp_path):
    with pytest.raises(KeyError):
        FileVaultBackend(tmp_path).resolve("ssh-key/nope")


def test_file_vault_rejects_path_traversal(tmp_path):
    with pytest.raises(KeyError):
        FileVaultBackend(tmp_path).resolve("../../etc/passwd")


# --- env vault ----------------------------------------------------------

def test_env_vault_resolves(monkeypatch):
    monkeypatch.setenv("AID_SECRET_SSH_KEY_VPS_01", "ENVKEY")
    assert EnvVaultBackend().resolve("ssh-key/vps-01") == "ENVKEY"


def test_env_vault_missing_raises():
    with pytest.raises(KeyError):
        EnvVaultBackend(prefix="AID_NOPE_").resolve("ssh-key/absent")


# --- dpkg parsing + SSH inspector ---------------------------------------

def test_parse_dpkg():
    out = "openssl 3.0.5-1\nbash 5.1-6ubuntu1\n\nbadline\n"
    assert _parse_dpkg(out) == {"openssl": "3.0.5-1", "bash": "5.1-6ubuntu1"}


class _VaultStub:
    def __init__(self):
        self.calls = []

    def resolve(self, ref, *, actor, reason):
        self.calls.append((ref, actor, reason))
        return "KEY"


class _TransportStub:
    def __init__(self, output):
        self.output = output
        self.calls = []

    def run(self, host, argv, *, key, timeout, user="root", port=22):
        self.calls.append((host, user, port, tuple(argv), key))
        return self.output


def test_ssh_inspector_collects_packages():
    conn = ConnectionInfo(host="10.0.0.9", key_ref="ssh-key/h1", user="ubuntu", port=2222)
    vault = _VaultStub()
    transport = _TransportStub(CommandOutput(0, "openssl 3.0.5\nbash 5.1\n", ""))
    insp = SSHHostInspector(lambda a: conn, vault, transport)

    findings = insp.collect("h1")
    assert findings["installed_packages"] == {"openssl": "3.0.5", "bash": "5.1"}
    # resolved the key from the vault and connected to the registry's host/user/port
    assert vault.calls[0][0] == "ssh-key/h1"
    assert transport.calls[0][:3] == ("10.0.0.9", "ubuntu", 2222)


def test_ssh_inspector_reports_scan_failure():
    conn = ConnectionInfo(host="10.0.0.9", key_ref="ssh-key/h1")
    insp = SSHHostInspector(lambda a: conn, _VaultStub(),
                            _TransportStub(CommandOutput(127, "", "dpkg-query: not found")))
    findings = insp.collect("h1")
    assert findings["installed_packages"] == {}
    assert findings["misconfigurations"] and "scan failed" in findings["misconfigurations"][0]


# --- paramiko transport (fake paramiko) ---------------------------------

class _FakeChannel:
    def recv_exit_status(self):
        return 0


class _FakeStream:
    def __init__(self, data, chan=None):
        self._data = data
        self.channel = chan

    def read(self):
        return self._data


class _FakeSSHClient:
    last = {}

    def load_host_keys(self, path): _FakeSSHClient.last["known_hosts"] = path
    def load_system_host_keys(self): _FakeSSHClient.last["system_hosts"] = True
    def set_missing_host_key_policy(self, policy):
        _FakeSSHClient.last["policy"] = type(policy).__name__
    def connect(self, **kwargs): _FakeSSHClient.last["connect"] = kwargs
    def exec_command(self, command, timeout=None, get_pty=False):
        _FakeSSHClient.last["command"] = command
        _FakeSSHClient.last["get_pty"] = get_pty
        return (None, _FakeStream(b"done\n", _FakeChannel()), _FakeStream(b""))
    def close(self): _FakeSSHClient.last["closed"] = True


def _fake_paramiko():
    m = types.ModuleType("paramiko")
    m.SSHException = type("SSHException", (Exception,), {})
    class _Key:
        @classmethod
        def from_private_key(cls, *a, **k): return object()
    m.Ed25519Key = _Key
    m.RSAKey = _Key
    m.SSHClient = _FakeSSHClient
    m.AutoAddPolicy = type("AutoAddPolicy", (), {})
    m.RejectPolicy = type("RejectPolicy", (), {})
    return m


def test_paramiko_transport_runs_and_verifies_host_keys(monkeypatch):
    monkeypatch.setitem(sys.modules, "paramiko", _fake_paramiko())
    from ai_defense.ssh.paramiko_transport import ParamikoTransport

    t = ParamikoTransport()                       # host-key verification ON by default
    out = t.run("host1", ["apt-get", "install", "-y", "openssl"],
                key="KEYDATA", timeout=30, user="ubuntu", port=2222)
    assert out.exit_code == 0 and out.stdout == "done\n"
    last = _FakeSSHClient.last
    assert last["policy"] == "RejectPolicy"       # not AutoAdd by default
    assert last["connect"]["hostname"] == "host1" and last["connect"]["username"] == "ubuntu"
    assert last["connect"]["port"] == 2222
    assert last["get_pty"] is False               # non-interactive
    assert "openssl" in last["command"] and "KEYDATA" not in last["command"]
    assert last["closed"] is True


def test_paramiko_transport_allow_unknown_uses_autoadd(monkeypatch):
    monkeypatch.setitem(sys.modules, "paramiko", _fake_paramiko())
    from ai_defense.ssh.paramiko_transport import ParamikoTransport

    ParamikoTransport(allow_unknown_hosts=True).run("h", ["true"], key="K", timeout=5)
    assert _FakeSSHClient.last["policy"] == "AutoAddPolicy"
