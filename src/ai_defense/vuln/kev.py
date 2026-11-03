"""CISA KEV (Known Exploited Vulnerabilities) enrichment.

Wraps any ``AdvisoryFeed`` and flips ``kev=True`` on advisories whose CVE is in
CISA's KEV catalog — "actively exploited in the wild", which the planner ranks
above everything else. The catalog is fetched over the injected HTTP client
(stdlib by default), so this is testable offline.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from .feeds import Advisory, AdvisoryFeed
from .osv import HttpClient, UrllibHttpClient

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


class KevCatalog:
    """The set of CVE IDs CISA lists as known-exploited. Fetched once, cached."""

    def __init__(self, http_client: HttpClient | None = None, *, url: str = KEV_URL) -> None:
        self._http = http_client or UrllibHttpClient()
        self._url = url
        self._cache: set[str] | None = None

    def cve_ids(self) -> set[str]:
        if self._cache is None:
            data = self._http.get_json(self._url)
            self._cache = {v["cveID"] for v in data.get("vulnerabilities", [])
                           if v.get("cveID")}
        return self._cache

    def contains(self, cve_id: str) -> bool:
        return cve_id in self.cve_ids()


class KevEnrichedFeed(AdvisoryFeed):
    """Decorator: runs an inner feed, then marks KEV-listed advisories."""

    def __init__(self, inner: AdvisoryFeed, catalog: KevCatalog) -> None:
        self._inner = inner
        self._catalog = catalog

    def fetch(self, since: datetime | None = None) -> list[Advisory]:
        return self._enrich(self._inner.fetch(since))

    def for_inventory(self, inventory) -> list[Advisory]:
        return self._enrich(self._inner.for_inventory(inventory))

    def _enrich(self, advisories: list[Advisory]) -> list[Advisory]:
        kev = self._catalog.cve_ids()
        return [replace(a, kev=True) if (not a.kev and a.cve_id in kev) else a
                for a in advisories]
