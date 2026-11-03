"""SSHExecutor unit tests against a fake transport (no real hosts)."""

import pytest

from ai_defense.ssh.catalog import CATALOG, render_argv
from ai_defense.ssh.executor import CommandOutput, SSHExecutor


class FakeTransport:
    """Records every argv it is asked to run and returns scripted outputs.

    ``script`` maps a tuple(argv) -> CommandOutput; unmatched argvs return exit 0.
    """

    def __init__(self, script=None, default=CommandOutput(0, "ok", "")):
        self.script = script or {}
        self.default = default
        self.calls = []          # list of (host, argv, key, timeout)

    def run(self, host, argv, *, key, timeout, user="root", port=22):
        self.calls.append((host, tuple(argv), key, timeout))
        return self.script.get(tuple(argv), self.default)


def test_render_rejects_unsafe_value():
    with pytest.raises(ValueError):
        render_argv(["apt-get", "install", "{package}"], {"package": "openssl; rm -rf /"})


def test_render_requires_all_params():
    with pytest.raises(KeyError):
        render_argv(["apt-get", "install", "{package}"], {})


def test_unknown_template_raises():
    ex = SSHExecutor(FakeTransport())
    with pytest.raises(KeyError):
        ex.run_template("h", "nope.unknown", {}, key="k")


def test_dry_run_runs_before_apply():
    t = FakeTransport()
    ex = SSHExecutor(t)
    outcome = ex.run_template("h", "apt.install_security", {"package": "openssl"}, key="k")
    assert outcome.applied
    # two transport calls: dry-run (--simulate) then the real apply
    assert len(t.calls) == 2
    assert "--simulate" in t.calls[0][1]
    assert "--simulate" not in t.calls[1][1]


def test_failed_dry_run_aborts_apply():
    dry_argv = tuple(CATALOG["apt.install_security"].render_dry_run({"package": "openssl"}))
    t = FakeTransport(script={dry_argv: CommandOutput(100, "", "would break deps")})
    ex = SSHExecutor(t)
    outcome = ex.run_template("h", "apt.install_security", {"package": "openssl"}, key="k")
    assert not outcome.applied
    assert "dry-run failed" in outcome.blocked_reason
    assert len(t.calls) == 1          # apply never happened


def test_key_never_in_resolved_command():
    t = FakeTransport()
    ex = SSHExecutor(t)
    outcome = ex.run_template("h", "apt.install_security", {"package": "openssl"},
                              key="SUPER-SECRET-KEY")
    assert "SUPER-SECRET-KEY" not in outcome.resolved_command
    # key reached the transport (to connect) but only as the dedicated arg
    assert all(call[2] == "SUPER-SECRET-KEY" for call in t.calls)


def test_output_is_capped():
    big = "x" * 100_000
    t = FakeTransport(default=CommandOutput(0, big, big))
    ex = SSHExecutor(t, max_output_bytes=1000)
    outcome = ex.run_template("h", "apt.install_security", {"package": "openssl"}, key="k")
    assert len(outcome.result.stdout) < len(big)
    assert outcome.result.stdout.endswith("...[truncated]")
