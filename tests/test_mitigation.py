"""Published-mitigation path: apply a cited, reversible workaround (PwnKit pkexec
SUID strip) where the vendor patch can't be installed — allowlisted command only,
approval-gated, with a recorded rollback."""

from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_demo_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.ssh.catalog import CATALOG
from ai_defense.ssh.executor import CommandOutput, SSHExecutor
from ai_defense.ssh.tools import make_mitigation_tool
from ai_defense.toolset.registry import ToolCapability
from ai_defense.vuln.mitigations import mitigation_for


def _host(asset_id="h") -> Asset:
    now = datetime.now(UTC)
    return Asset(
        asset_id, "ssh-host", "ops", "prod",
        Authorization("sig", "op", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01",
                                  user="ubuntu"))


# --- cited table + allowlisted command ----------------------------------

def test_mitigation_table_is_cited():
    m = mitigation_for("CVE-2021-4034")
    assert m is not None and m.mitigation_id == "pwnkit-pkexec-suid"
    assert "pkexec" in m.title.lower()
    assert "CVE-2021-4034" in m.source_ref           # human-verifiable advisory link
    assert mitigation_for("CVE-0000-0000") is None   # uncatalogued -> escalate


def test_catalog_commands_are_fixed_and_reversible():
    disable = CATALOG["harden.disable_pkexec_suid"]
    restore = CATALOG["harden.restore_pkexec_suid"]
    assert disable.render({}) == ["chmod", "0755", "/usr/bin/pkexec"]
    assert restore.render({}) == ["chmod", "4755", "/usr/bin/pkexec"]
    assert disable.render_dry_run({}) == ["stat", "-c", "%a %n", "/usr/bin/pkexec"]


# --- tool: allowlisted id only, dry-run first, records rollback ----------

class _OkTransport:
    def __init__(self):
        self.argv = []

    def run(self, host, argv, *, key, timeout, user="root", port=22):
        self.argv.append(tuple(argv))
        return CommandOutput(0, "ok", "")


def test_mitigation_tool_applies_and_records_rollback():
    tp = _OkTransport()
    spec = make_mitigation_tool(SSHExecutor(tp),
                                lambda aid: ConnectionInfo(host="1.1.1.1", key_ref="k"))
    assert spec.capability is ToolCapability.MUTATING
    res = spec.executor({"asset_id": "h", "mitigation_id": "pwnkit-pkexec-suid"},
                        resolve_secret=lambda ref: "KEY")
    assert res.ok and res.data["mitigation_id"] == "pwnkit-pkexec-suid"
    assert res.data["rollback"]["payload"]["rollback_template"] == "harden.restore_pkexec_suid"
    assert res.resolved_command == "chmod 0755 /usr/bin/pkexec"
    assert ("stat", "-c", "%a %n", "/usr/bin/pkexec") in tp.argv   # dry-run ran first


def test_mitigation_tool_refuses_unknown_id():
    spec = make_mitigation_tool(SSHExecutor(_OkTransport()),
                                lambda aid: ConnectionInfo(host="1.1.1.1", key_ref="k"))
    res = spec.executor({"asset_id": "h", "mitigation_id": "chmod-anything"},
                        resolve_secret=lambda ref: "KEY")
    assert not res.ok and "unknown mitigation" in res.summary


# --- engine (approval-gated) + MCP --------------------------------------

def test_engine_mitigate_is_gated_then_applies():
    eng = build_demo_engine()
    eng.registry.register(_host("h"))
    pending = eng.mitigate("h", "CVE-2021-4034")
    assert not pending.ok and pending.data["approval_state"] == "pending"
    eng.approve(pending.data["change_set_id"])
    done = eng.mitigate("h", "CVE-2021-4034")
    assert done.ok and done.data["mitigation_id"] == "pwnkit-pkexec-suid"
    assert "rollback" in done.data


def test_engine_mitigate_escalates_uncatalogued_cve():
    eng = build_demo_engine()
    eng.registry.register(_host("h"))
    res = eng.mitigate("h", "CVE-2099-0001")
    assert not res.ok and "no catalogued mitigation" in res.summary


def test_mcp_mitigate_pending_then_applies():
    eng = build_demo_engine()
    eng.registry.register(_host("h"))
    out = handle_call(eng, "mitigate", {"asset_id": "h", "cve": "CVE-2021-4034"})
    assert out["ok"] is False and out.get("change_set_id")
    handle_call(eng, "approve_change", {"change_set_id": out["change_set_id"]})
    out2 = handle_call(eng, "mitigate", {"asset_id": "h", "cve": "CVE-2021-4034"})
    assert out2["ok"] is True
