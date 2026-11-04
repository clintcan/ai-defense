"""remediate/plan fail-safe: a throttled or incomplete advisory fetch (and an
unscannable host) must never read as a clean 'no patch available'."""

from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_demo_engine, build_engine
from ai_defense.mcp_server import handle_call
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.vuln.osv import OsvFeed


class _DownOsv:
    """Every query batch fails -> for_inventory degrades to no advisories."""

    def post_json(self, url, body):
        raise OSError("osv throttled")

    def get_json(self, url):
        raise AssertionError("no detail fetch when the batch failed")


class _EmptyOsv:
    """Succeeds but finds nothing — a genuine clean result (no degradation)."""

    def post_json(self, url, body):
        return {"results": [{} for _ in body["queries"]]}

    def get_json(self, url):
        raise AssertionError("no detail fetch when there are no vulns")


# --- engine health signal ------------------------------------------------

def test_engine_reports_feed_health():
    down = build_demo_engine(advisory_feed=OsvFeed(_DownOsv()))
    down.build_report(["any-host"])                    # runs for_inventory (degrades)
    degraded, note = down.advisory_feed_health()
    assert degraded is True and "batch" in note

    clean = build_demo_engine(advisory_feed=OsvFeed(_EmptyOsv()))
    clean.build_report(["any-host"])
    assert clean.advisory_feed_health() == (False, None)


# --- remediate distinguishes the three negatives ------------------------

def test_remediate_undetermined_on_degraded_feed():
    eng = build_demo_engine(advisory_feed=OsvFeed(_DownOsv()))
    out = handle_call(eng, "remediate", {"asset_id": "any-host", "package": "openssl"})
    assert out["status"] == "undetermined"
    low = out["detail"].lower()
    assert "incomplete" in low and "not" in low        # explicitly not a clean negative


def test_remediate_no_patch_when_feed_is_clean():
    eng = build_demo_engine(advisory_feed=OsvFeed(_EmptyOsv()))
    out = handle_call(eng, "remediate", {"asset_id": "any-host", "package": "openssl"})
    assert out["status"] == "no_patch_available"       # honest: feed was complete


def test_remediate_scan_failed_is_distinct():
    class _Dead:
        def collect(self, asset_id):
            raise OSError("connection refused")

    eng = build_engine(inspector=_Dead())
    out = handle_call(eng, "remediate", {"asset_id": "h", "package": "openssl"})
    assert out["status"] == "scan_failed" and "could not scan" in out["detail"]


def test_remediate_happy_path_still_pends():
    # demo static feed: openssl has a real patch item -> normal pending change-set
    eng = build_demo_engine()
    now = datetime.now(UTC)
    eng.registry.register(Asset(
        "vps-demo-01", "ssh-host", "ops", "prod",
        Authorization("sig", "op", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="198.51.100.20", key_ref="ssh-key/vps-demo-01",
                                  user="ubuntu")))
    out = handle_call(eng, "remediate", {"asset_id": "vps-demo-01", "package": "openssl"})
    assert out["status"] != "no_patch_available"       # found + proposed (pending)
    assert out.get("change_set_id")


# --- plan handler flags a degraded (thin) plan --------------------------

def test_plan_flags_degraded_feed():
    eng = build_demo_engine(advisory_feed=OsvFeed(_DownOsv()))
    out = handle_call(eng, "plan", {"asset_ids": ["any-host"]})
    assert out.get("feed_degraded") is True and out["plan"] == []

    clean = build_demo_engine(advisory_feed=OsvFeed(_EmptyOsv()))
    out2 = handle_call(clean, "plan", {"asset_ids": ["any-host"]})
    assert "feed_degraded" not in out2                 # clean plan carries no flag
