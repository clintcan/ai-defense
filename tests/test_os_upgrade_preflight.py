"""OS-upgrade preflight: release knowledge base, the read-only planner, the
scanner probe path, the SSH inspector probes, and engine/MCP wiring."""

from datetime import date

from ai_defense.composition import build_demo_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import ConnectionInfo
from ai_defense.scanner.scanner import AuthenticatedScanner, HostFindings
from ai_defense.scanner.ssh_inspector import SSHHostInspector, _parse_df_free_mb
from ai_defense.ssh.executor import CommandOutput
from ai_defense.upgrade import releases
from ai_defense.upgrade.preflight import OsUpgradePreflight, UpgradeVerdict

NOW = date(2026, 11, 4)


# --- release knowledge base ---------------------------------------------

def test_lookup_and_path():
    assert releases.lookup("ubuntu", "18.04").codename == "bionic"
    assert releases.lookup("ubuntu", "99.99") is None
    assert releases.next_release("ubuntu", "18.04").version == "20.04"
    assert [r.version for r in releases.path_to_latest("ubuntu", "18.04")] == \
        ["20.04", "22.04", "24.04"]
    # newest known release has no successor
    assert releases.next_release("ubuntu", "24.04") is None
    assert releases.path_to_latest("debian", "10") == releases.path_to_latest("debian", "10")
    assert [r.version for r in releases.path_to_latest("debian", "10")] == ["11", "12", "13"]


def test_support_status_transitions():
    bionic = releases.lookup("ubuntu", "18.04")
    assert releases.support_status(bionic, date(2022, 1, 1)) == "supported"
    assert releases.support_status(bionic, NOW) == "esm"          # past standard, within ESM
    assert releases.support_status(bionic, date(2029, 1, 1)) == "eol"
    buster = releases.lookup("debian", "10")                      # no ESM phase in our table
    assert releases.support_status(buster, NOW) == "eol"


# --- preflight planner ---------------------------------------------------

def _findings(os_release, system_state=None):
    return HostFindings("h1", os_release=os_release, system_state=system_state or {})


def test_ready_when_target_exists_and_no_blockers():
    f = _findings({"ID": "ubuntu", "VERSION_ID": "18.04"},
                  {"reboot_required": False, "disk_free_mb": 20000,
                   "held_packages": [], "broken_packages_report": ""})
    r = OsUpgradePreflight().assess(f, NOW)
    assert r.verdict is UpgradeVerdict.READY
    assert r.target_version == "20.04" and r.target_codename == "focal"
    assert r.support_status == "esm"
    assert r.path == ["20.04", "22.04", "24.04"]
    assert r.blockers == []
    assert any("Ubuntu Pro" in n or "extended" in n for n in r.notes)
    assert any("makes no change" in n for n in r.notes)   # preflight is read-only


def test_blocked_lists_every_probe_blocker():
    f = _findings({"ID": "ubuntu", "VERSION_ID": "18.04"},
                  {"reboot_required": True, "disk_free_mb": 1000,
                   "held_packages": ["linux-image-generic"],
                   "broken_packages_report": "The following packages are broken: foo"})
    r = OsUpgradePreflight(min_free_mb=5120).assess(f, NOW)
    assert r.verdict is UpgradeVerdict.BLOCKED
    codes = {b.code for b in r.blockers}
    assert codes == {"pending_reboot", "low_disk", "held_packages", "broken_packages"}


def test_eol_is_flagged_urgent():
    f = _findings({"ID": "ubuntu", "VERSION_ID": "18.04"},
                  {"reboot_required": False, "disk_free_mb": 20000})
    r = OsUpgradePreflight().assess(f, date(2029, 1, 1))
    assert r.support_status == "eol"
    assert any("END OF LIFE" in n for n in r.notes)


def test_current_when_on_newest_release():
    r = OsUpgradePreflight().assess(_findings({"ID": "ubuntu", "VERSION_ID": "24.04"}), NOW)
    assert r.verdict is UpgradeVerdict.CURRENT
    assert r.target_version is None and r.path == []


def test_unknown_distro_escalates():
    r = OsUpgradePreflight().assess(_findings({"ID": "fedora", "VERSION_ID": "40"}), NOW)
    assert r.verdict is UpgradeVerdict.UNKNOWN
    assert r.target_version is None
    assert any("not in the supported release table" in n for n in r.notes)


def test_missing_probes_do_not_fake_readiness():
    # No system_state: a target exists, but the report says readiness is unverified.
    r = OsUpgradePreflight().assess(_findings({"ID": "debian", "VERSION_ID": "11"}), NOW)
    assert r.verdict is UpgradeVerdict.READY      # path is known
    assert r.target_version == "12"
    assert any("probes were not collected" in n for n in r.notes)


# --- scanner probe path --------------------------------------------------

class _ProbeInspector:
    def collect(self, asset_id):
        return {"installed_packages": {"openssl": "1.1.1"},
                "os_release": {"ID": "ubuntu", "VERSION_ID": "20.04"}}

    def collect_upgrade_state(self, asset_id):
        return {"reboot_required": True, "disk_free_mb": 9000,
                "held_packages": [], "broken_packages_report": ""}


class _BareInspector:
    def collect(self, asset_id):
        return {"installed_packages": {"openssl": "1.1.1"},
                "os_release": {"ID": "ubuntu", "VERSION_ID": "20.04"}}


def test_scan_for_upgrade_merges_probes_but_plain_scan_stays_lean():
    scanner = AuthenticatedScanner(_ProbeInspector())
    lean = scanner.scan_host("h1")
    assert lean.system_state == {}                       # normal scan does not probe
    assert lean.os_release["VERSION_ID"] == "20.04"
    full = scanner.scan_host_for_upgrade("h1")
    assert full.system_state["reboot_required"] is True

    # an inspector without the probe method still works (no system_state)
    assert AuthenticatedScanner(_BareInspector()).scan_host_for_upgrade("h1").system_state == {}


# --- SSH inspector probes ------------------------------------------------

def test_parse_df_free_mb():
    out = ("Filesystem     1024-blocks    Used Available Capacity Mounted on\n"
           "/dev/root         40593708 5000000  30000000      14% /\n")
    assert _parse_df_free_mb(out) == 30000000 // 1024
    assert _parse_df_free_mb("header only\n") is None


class _VaultStub:
    def resolve(self, ref, *, actor, reason):
        return "KEY"


class _ScriptedTransport:
    """Returns a canned output per probe command."""

    def run(self, host, argv, *, key, timeout, user="root", port=22):
        if argv[:2] == ["test", "-f"]:
            return CommandOutput(0, "", "")                      # reboot pending (exit 0)
        if argv[0] == "df":
            return CommandOutput(0, "hdr\n/dev/root 40 1 20971520 5% /\n", "")
        if argv == ["apt-mark", "showhold"]:
            return CommandOutput(0, "linux-image-generic\n\n", "")
        if argv == ["dpkg", "--audit"]:
            return CommandOutput(0, "", "")                      # clean
        return CommandOutput(1, "", "unexpected")


def test_ssh_inspector_collect_upgrade_state():
    conn = ConnectionInfo(host="h", key_ref="ssh-key/h")
    insp = SSHHostInspector(lambda a: conn, _VaultStub(), _ScriptedTransport())
    st = insp.collect_upgrade_state("h")
    assert st["reboot_required"] is True
    assert st["disk_free_mb"] == 20971520 // 1024
    assert st["held_packages"] == ["linux-image-generic"]
    assert st["broken_packages_report"] == ""


# --- engine + MCP wiring -------------------------------------------------

def test_engine_upgrade_preflight_on_demo():
    eng = build_demo_engine()                 # demo host is ubuntu 18.04, clean probes
    reports = eng.upgrade_preflight(["any-host"])
    assert len(reports) == 1
    r = reports[0]
    assert r.current_os.startswith("ubuntu 18.04")
    assert r.target_version == "20.04"
    assert r.verdict is UpgradeVerdict.READY


def test_mcp_handle_call_upgrade_preflight():
    eng = build_demo_engine()
    out = handle_call(eng, "upgrade_preflight", {"asset_ids": ["any-host"]})
    assert "reports" in out and len(out["reports"]) == 1
    rep = out["reports"][0]
    assert rep["target_version"] == "20.04"
    assert rep["verdict"] in {"ready", "blocked"}
    assert rep["source_ref"]


_OK_STATE = {"reboot_required": False, "disk_free_mb": 20480,
             "held_packages": [], "broken_packages_report": ""}


def test_debian_hop_onto_an_eol_release_is_blocked():
    # db-proxy-1, 2026-11-05: buster -> bullseye after bullseye's LTS ended;
    # its security pool had moved to archive.debian.org, so full-upgrade 404'd.
    r = OsUpgradePreflight().assess(
        _findings({"ID": "debian", "VERSION_ID": "10"}, _OK_STATE), NOW)
    assert r.verdict is UpgradeVerdict.BLOCKED
    b = next(b for b in r.blockers if b.code == "target_eol")
    assert "debian 11" in b.detail and "Rebuild on debian 13" in b.detail


def test_debian_hop_before_target_eol_is_ready():
    r = OsUpgradePreflight().assess(
        _findings({"ID": "debian", "VERSION_ID": "10"}, _OK_STATE), date(2026, 1, 1))
    assert r.verdict is UpgradeVerdict.READY and r.target_version == "11"


def test_ubuntu_hop_onto_an_eol_release_is_not_blocked_by_this_rule():
    # do-release-upgrade handles EOL intermediates via old-releases.ubuntu.com
    r = OsUpgradePreflight().assess(
        _findings({"ID": "ubuntu", "VERSION_ID": "16.04"}, _OK_STATE), date(2040, 1, 1))
    assert not any(b.code == "target_eol" for b in r.blockers)
