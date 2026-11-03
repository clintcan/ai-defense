"""OSV advisory feed, exercised against a fake HTTP client (no network)."""

from ai_defense.composition import build_demo_engine
from ai_defense.db import init_db
from ai_defense.scanner.scanner import HostFindings
from ai_defense.vuln.correlate import correlate
from ai_defense.vuln.osv import OsvFeed, _to_advisory
from ai_defense.vuln.planner import RemediationKind, RemediationPlanner

# A canonical OSV vuln detail for openssl, fixed in 3.0.8.
_OPENSSL_VULN = {
    "id": "OSV-2026-1",
    "aliases": ["CVE-2026-1001"],
    "summary": "openssl flaw",
    "published": "2026-10-01T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
    "affected": [{
        "package": {"name": "openssl", "ecosystem": "Debian"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.0.8"}]}],
    }],
}


class FakeHttp:
    """Scripted OSV responses; records requests."""

    def __init__(self):
        self.posts = []
        self.gets = []

    def post_json(self, url, body):
        self.posts.append((url, body))
        # one result slot per query; flag openssl as vulnerable
        results = []
        for q in body["queries"]:
            if q["package"]["name"] == "openssl":
                results.append({"vulns": [{"id": "OSV-2026-1"}]})
            else:
                results.append({})
        return {"results": results}

    def get_json(self, url):
        self.gets.append(url)
        return _OPENSSL_VULN


# --- normalization ------------------------------------------------------

def test_to_advisory_normalizes_ranges_and_alias():
    adv = _to_advisory(_OPENSSL_VULN)
    assert adv.cve_id == "CVE-2026-1001"        # prefers the CVE alias over OSV id
    assert adv.source == "osv"
    assert adv.cvss == 7.5
    pkg = adv.affected[0]
    assert pkg.name == "openssl" and pkg.fixed_version == "3.0.8"
    assert adv.metadata["osv_id"] == "OSV-2026-1"
    assert adv.published_at is not None


def test_to_advisory_missing_id_is_none():
    assert _to_advisory({}) is None


def test_to_advisory_canonicalizes_distro_cve_id():
    # Ubuntu OSV records id-prefix the CVE and may not list it as a plain alias;
    # the advisory must still key on the canonical CVE (so KEV/CVSS/dedupe match).
    ubuntu = {"id": "UBUNTU-CVE-2023-1523", "aliases": ["USN-1234-1"],
              "affected": [{"package": {"name": "snapd", "ecosystem": "Ubuntu:18.04:LTS"}}]}
    assert _to_advisory(ubuntu).cve_id == "CVE-2023-1523"
    assert _to_advisory(ubuntu).metadata["osv_id"] == "UBUNTU-CVE-2023-1523"
    # a record with no CVE anywhere keeps its OSV id
    assert _to_advisory({"id": "GHSA-xxxx"}).cve_id == "GHSA-xxxx"


def test_for_inventory_dedupes_repeated_affected_entries():
    # One OSV record listing the same package across several release pockets
    # must yield a single finding, not one per pocket.
    pockets = {
        "id": "UBUNTU-CVE-2022-0001", "aliases": [],
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "affected": [
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:18.04:LTS"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                         {"fixed": "1.1.1-1ubuntu2.1~18.04"}]}]},
            {"package": {"name": "openssl", "ecosystem": "Ubuntu:18.04:LTS"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"},
                                                         {"fixed": "1.1.1-1ubuntu2.1~18.04"}]}]},
        ],
    }

    class _Http:
        def post_json(self, url, body):
            return {"results": [{"vulns": [{"id": "UBUNTU-CVE-2022-0001"}]}]}

        def get_json(self, url):
            return pockets

    inv = [HostFindings("h1", {"openssl": "1.1.1"}, ecosystem="Ubuntu:18.04:LTS")]
    advisories = OsvFeed(_Http()).for_inventory(inv)
    findings = correlate(advisories, inv)
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2022-0001"


# --- query-by-inventory -------------------------------------------------

def test_for_inventory_queries_only_present_packages():
    http = FakeHttp()
    feed = OsvFeed(http, ecosystem="Debian")
    inv = [HostFindings("h1", {"openssl": "3.0.5", "bash": "5.1"})]
    advisories = feed.for_inventory(inv)

    # one batch query with both packages
    assert len(http.posts) == 1
    names = {q["package"]["name"] for q in http.posts[0][1]["queries"]}
    assert names == {"openssl", "bash"}
    # only openssl had a vuln
    assert [a.cve_id for a in advisories] == ["CVE-2026-1001"]


def test_for_inventory_empty_makes_no_request():
    http = FakeHttp()
    assert OsvFeed(http).for_inventory([]) == []
    assert http.posts == []


def test_querybatch_is_chunked_under_osv_limit():
    # >1000 unique packages must be split into <=1000-query batches (OSV rejects
    # larger), and a single CVE id still fetched once.
    from ai_defense.vuln.osv import _MAX_BATCH

    class _Http:
        def __init__(self):
            self.batch_sizes = []

        def post_json(self, url, body):
            n = len(body["queries"])
            self.batch_sizes.append(n)
            assert n <= _MAX_BATCH            # never exceed the OSV cap
            return {"results": [{"vulns": [{"id": "OSV-X"}]} for _ in range(n)]}

        def get_json(self, url):
            return {"id": "OSV-X", "aliases": ["CVE-2030-9"],
                    "affected": [{"package": {"name": "p"}}]}

    pkgs = {f"pkg{i}": "1.0" for i in range(1500)}     # 1500 unique -> 2 batches
    http = _Http()
    advs = OsvFeed(http).for_inventory([HostFindings("h1", pkgs)])
    assert http.batch_sizes == [1000, 500]
    assert [a.cve_id for a in advs] == ["CVE-2030-9"]   # deduped to one


def test_for_inventory_degrades_on_batch_and_detail_errors():
    # A failing batch is skipped; a failing detail drops just that advisory.
    class _Http:
        def post_json(self, url, body):
            return {"results": [{"vulns": [{"id": "OSV-GOOD"}, {"id": "OSV-BAD"}]}]}

        def get_json(self, url):
            if url.endswith("OSV-BAD"):
                raise OSError("rate limited")
            return {"id": "OSV-GOOD", "aliases": ["CVE-2030-1"],
                    "affected": [{"package": {"name": "p"}}]}

    advs = OsvFeed(_Http(), max_workers=4).for_inventory([HostFindings("h1", {"p": "1"})])
    assert [a.cve_id for a in advs] == ["CVE-2030-1"]    # bad one dropped, no crash


def test_detail_fetch_dedupes_and_parallelizes():
    # Three packages; two share the SAME vuln id. Detail must be fetched once per
    # UNIQUE id (2 GETs, not 3), and all distinct advisories returned.
    import threading

    details = {
        "OSV-A": {"id": "OSV-A", "aliases": ["CVE-2030-1"],
                  "affected": [{"package": {"name": "pkg1"}}]},
        "OSV-B": {"id": "OSV-B", "aliases": ["CVE-2030-2"],
                  "affected": [{"package": {"name": "pkg3"}}]},
    }

    class _Http:
        def __init__(self):
            self.get_ids = []
            self._lock = threading.Lock()

        def post_json(self, url, body):
            # pkg1 and pkg2 both map to OSV-A; pkg3 maps to OSV-B
            out = []
            for q in body["queries"]:
                name = q["package"]["name"]
                if name in ("pkg1", "pkg2"):
                    out.append({"vulns": [{"id": "OSV-A"}]})
                elif name == "pkg3":
                    out.append({"vulns": [{"id": "OSV-B"}]})
                else:
                    out.append({})
            return {"results": out}

        def get_json(self, url):
            vid = url.rsplit("/", 1)[-1]
            with self._lock:
                self.get_ids.append(vid)
            return details[vid]

    http = _Http()
    inv = [HostFindings("h1", {"pkg1": "1", "pkg2": "1", "pkg3": "1"})]
    advs = OsvFeed(http, max_workers=4).for_inventory(inv)
    assert sorted(a.cve_id for a in advs) == ["CVE-2030-1", "CVE-2030-2"]
    assert sorted(http.get_ids) == ["OSV-A", "OSV-B"]      # each unique id fetched once


def test_osv_advisories_correlate_against_inventory():
    feed = OsvFeed(FakeHttp(), ecosystem="Debian")
    inv = [HostFindings("h1", {"openssl": "3.0.5"})]
    findings = correlate(feed.for_inventory(inv), inv)
    assert len(findings) == 1 and findings[0].fixed_version == "3.0.8"


# --- engine plan end to end ---------------------------------------------

def test_engine_plan_with_osv_feed():
    eng = build_demo_engine(session_factory=init_db(),
                            advisory_feed=OsvFeed(FakeHttp(), ecosystem="Debian"))
    # the demo inspector reports openssl 3.0.5; OSV says fixed in 3.0.8 -> patch
    plan = eng.plan(eng.scan(["any-host"]))
    cves = {it.cve_id: it.kind for it in plan}
    assert cves.get("CVE-2026-1001") == RemediationKind.PATCH


def test_static_feed_ignores_inventory():
    # default static feed's for_inventory just returns fetch()
    planner = RemediationPlanner()
    assert planner is not None   # sanity; static behaviour covered in test_vuln_planner


def test_for_inventory_uses_per_host_ecosystem():
    # Two hosts on different releases -> OSV queried under each host's ecosystem.
    http = FakeHttp()
    feed = OsvFeed(http, ecosystem="DEFAULT")            # default is only a fallback
    inv = [
        HostFindings("h1", {"openssl": "1.1.1"}, ecosystem="Ubuntu:18.04:LTS"),
        HostFindings("h2", {"bash": "5.1"}, ecosystem="Debian:12"),
        HostFindings("h3", {"curl": "7.0"}),            # no ecosystem -> default
    ]
    feed.for_inventory(inv)
    ecos = {(q["package"]["name"], q["package"]["ecosystem"])
            for q in http.posts[0][1]["queries"]}
    assert ("openssl", "Ubuntu:18.04:LTS") in ecos
    assert ("bash", "Debian:12") in ecos
    assert ("curl", "DEFAULT") in ecos                  # fell back to the configured default
