"""CISA KEV catalog + enrichment feed (offline via a fake HTTP client)."""

from ai_defense.composition import build_demo_engine
from ai_defense.db import init_db
from ai_defense.scanner.scanner import HostFindings
from ai_defense.vuln.feeds import Advisory, AffectedPackage, StaticAdvisoryFeed
from ai_defense.vuln.kev import KevCatalog, KevEnrichedFeed


class FakeHttp:
    def __init__(self, cve_ids):
        self._cve_ids = cve_ids
        self.gets = 0

    def get_json(self, url):
        self.gets += 1
        return {"vulnerabilities": [{"cveID": c} for c in self._cve_ids]}

    def post_json(self, url, body):
        raise AssertionError("KEV catalog should not POST")


def _adv(cve, kev=False):
    return Advisory(cve, "osv", [AffectedPackage("openssl", fixed_version="3.0.8")],
                    cvss=7.5, kev=kev)


# --- catalog ------------------------------------------------------------

def test_catalog_parses_and_caches():
    http = FakeHttp(["CVE-2026-1001", "CVE-2024-9"])
    cat = KevCatalog(http)
    assert cat.contains("CVE-2026-1001")
    assert not cat.contains("CVE-2000-0")
    cat.cve_ids()                      # second access
    assert http.gets == 1              # fetched once, cached


# --- enrichment ---------------------------------------------------------

def test_enrich_marks_kev_listed_only():
    inner = StaticAdvisoryFeed([_adv("CVE-2026-1001"), _adv("CVE-2026-2002")])
    feed = KevEnrichedFeed(inner, KevCatalog(FakeHttp(["CVE-2026-1001"])))
    by_id = {a.cve_id: a for a in feed.fetch()}
    assert by_id["CVE-2026-1001"].kev is True       # listed -> flagged
    assert by_id["CVE-2026-2002"].kev is False      # not listed -> unchanged


def test_enrich_matches_canonicalized_distro_cve():
    # A distro OSV record whose id is UBUNTU-CVE-... is normalized to the plain
    # CVE in _to_advisory, so KEV (keyed on CVE ids) now matches it.
    from ai_defense.vuln.osv import _to_advisory
    adv = _to_advisory({"id": "UBUNTU-CVE-2023-1523", "aliases": [],
                        "affected": [{"package": {"name": "snapd"}}]})
    feed = KevEnrichedFeed(StaticAdvisoryFeed([adv]),
                           KevCatalog(FakeHttp(["CVE-2023-1523"])))
    assert feed.fetch()[0].kev is True


def test_enrich_passes_through_for_inventory():
    # the wrapper must preserve the query-by-inventory path of the inner feed
    class _Inner(StaticAdvisoryFeed):
        def for_inventory(self, inventory):
            return [_adv("CVE-2026-1001")]
    feed = KevEnrichedFeed(_Inner([]), KevCatalog(FakeHttp(["CVE-2026-1001"])))
    advs = feed.for_inventory([HostFindings("h1", {"openssl": "3.0.5"})])
    assert advs[0].kev is True


# --- end to end: KEV bumps priority -------------------------------------

def test_kev_bumps_plan_priority():
    adv = _adv("CVE-2026-1001")                     # cvss 7.5, not yet KEV
    without = build_demo_engine(advisory_feed=StaticAdvisoryFeed([adv]))
    enriched = KevEnrichedFeed(StaticAdvisoryFeed([adv]),
                               KevCatalog(FakeHttp(["CVE-2026-1001"])))
    with_kev = build_demo_engine(session_factory=init_db(), advisory_feed=enriched)

    inv = without.scan(["any"])                      # demo inspector: openssl 3.0.5
    base_item = without.plan(inv)[0]
    kev_item = with_kev.plan(inv)[0]
    assert kev_item.priority >= base_item.priority + 1000   # KEV weight
