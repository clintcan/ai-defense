"""Vuln slice: version matching, correlation, scanner, and planner prioritization."""

from ai_defense.scanner.scanner import AuthenticatedScanner, HostFindings
from ai_defense.toolset.intents import ActionClass
from ai_defense.vuln.correlate import correlate
from ai_defense.vuln.feeds import (
    Advisory,
    AffectedPackage,
    StaticAdvisoryFeed,
    is_vulnerable,
    version_lt,
)
from ai_defense.vuln.planner import RemediationKind, RemediationPlanner

# --- version comparison -------------------------------------------------

def test_version_lt_basic():
    assert version_lt("1.0.0", "1.0.1")
    assert version_lt("1.9", "1.10")           # numeric, not lexical
    assert not version_lt("2.0", "1.9")
    assert not version_lt("1.0.0", "1.0.0")


def test_version_lt_mixed_tokens():
    assert version_lt("1.0.0-1ubuntu2", "1.0.0-1ubuntu3")


def test_is_vulnerable_bounds():
    pkg = AffectedPackage("openssl", fixed_version="3.0.8", introduced="3.0.0")
    assert is_vulnerable("3.0.5", pkg)         # in range
    assert not is_vulnerable("3.0.8", pkg)     # fixed
    assert not is_vulnerable("3.1.0", pkg)     # above fix
    assert not is_vulnerable("2.9.0", pkg)     # below introduced
    nopatch = AffectedPackage("foo", fixed_version=None, introduced="1.0")
    assert is_vulnerable("1.5", nopatch)       # no patch -> any >= introduced


# --- correlation --------------------------------------------------------

def _inv():
    return [
        HostFindings("h1", {"openssl": "3.0.5", "bash": "5.1"}),
        HostFindings("h2", {"openssl": "3.0.8"}),          # already fixed
        HostFindings("h3", {"nginx": "1.20"}),             # unaffected pkg
    ]


def test_correlate_matches_only_vulnerable_hosts():
    adv = Advisory("CVE-1", "osv", [AffectedPackage("openssl", fixed_version="3.0.8")])
    findings = correlate([adv], _inv())
    assert [f.asset_id for f in findings] == ["h1"]        # h2 fixed, h3 n/a
    assert findings[0].patch_available


# --- scanner ------------------------------------------------------------

class _FakeInspector:
    def collect(self, asset_id):
        return {"installed_packages": {"openssl": "3.0.5"},
                "applied_patches": ["KB1"], "misconfigurations": ["ssh-root-login"]}


def test_scanner_builds_findings():
    hf = AuthenticatedScanner(_FakeInspector()).scan_host("h1")
    assert hf.asset_id == "h1"
    assert hf.installed_packages["openssl"] == "3.0.5"
    assert hf.misconfigurations == ["ssh-root-login"]


# --- planner ------------------------------------------------------------

def _planner():
    return RemediationPlanner(key_ref_for=lambda a: f"ssh-key/{a}")


def test_plan_patch_item_builds_dispatchable_intent():
    adv = Advisory("CVE-1", "osv", [AffectedPackage("openssl", fixed_version="3.0.8")],
                   cvss=7.5)
    items = _planner().plan([adv], [HostFindings("h1", {"openssl": "3.0.5"})])
    assert len(items) == 1
    it = items[0]
    assert it.kind == RemediationKind.PATCH and not it.requires_human
    assert it.intent.tool == "patch.apply_security_update"
    assert it.intent.params == {"host": "h1", "package": "openssl", "key_ref": "ssh-key/h1"}
    assert it.intent.action_class == ActionClass.PATCH_CANARY
    assert it.intent.source_ref == "CVE-1"


def test_plan_mitigation_when_no_patch():
    adv = Advisory("CVE-2", "vendor", [AffectedPackage("foo", fixed_version=None)],
                   mitigation="disable the foo module in config", cvss=6.0)
    items = _planner().plan([adv], [HostFindings("h1", {"foo": "1.2"})])
    it = items[0]
    assert it.kind == RemediationKind.MITIGATION
    assert it.requires_human and it.intent is None
    assert "TEMPORARY" in it.note and it.tracking               # tracked follow-up


def test_plan_escalates_when_no_patch_no_mitigation():
    adv = Advisory("CVE-3", "osv", [AffectedPackage("bar", fixed_version=None)])
    items = _planner().plan([adv], [HostFindings("h1", {"bar": "0.9"})])
    assert items[0].kind == RemediationKind.ESCALATE and items[0].requires_human


def test_plan_prioritizes_kev_then_cvss():
    kev = Advisory("CVE-KEV", "kev", [AffectedPackage("a", fixed_version="2")],
                   cvss=5.0, kev=True)
    high = Advisory("CVE-HIGH", "osv", [AffectedPackage("b", fixed_version="2")],
                    cvss=9.8)
    low = Advisory("CVE-LOW", "osv", [AffectedPackage("c", fixed_version="2")],
                   cvss=3.1)
    inv = [HostFindings("h1", {"a": "1", "b": "1", "c": "1"})]
    order = [it.cve_id for it in _planner().plan([low, high, kev], inv)]
    assert order == ["CVE-KEV", "CVE-HIGH", "CVE-LOW"]          # KEV first, then CVSS


def test_static_feed_filters_by_since():
    from datetime import UTC, datetime
    a = Advisory("CVE-OLD", "osv", [], published_at=datetime(2026, 1, 1, tzinfo=UTC))
    b = Advisory("CVE-NEW", "osv", [], published_at=datetime(2026, 10, 1, tzinfo=UTC))
    feed = StaticAdvisoryFeed([a, b])
    got = feed.fetch(since=datetime(2026, 6, 1, tzinfo=UTC))
    assert [x.cve_id for x in got] == ["CVE-NEW"]
