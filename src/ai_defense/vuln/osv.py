"""OSV.dev advisory feed — query real vulnerabilities for observed packages.

Queries https://osv.dev by (ecosystem, package, version) using its batch API,
then fetches each vuln's detail and normalizes it to an ``Advisory``. The HTTP
client is injected (``HttpClient``) so this is testable without network; the
default ``UrllibHttpClient`` uses the standard library (no extra dependency).
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import re
import urllib.request
from datetime import datetime
from typing import Any, Protocol

from .feeds import Advisory, AdvisoryFeed, AffectedPackage

OSV_BASE = "https://api.osv.dev"
_DEFAULT_WORKERS = 8
_MAX_BATCH = 1000          # OSV querybatch rejects > 1000 queries per request (HTTP 400)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


class HttpClient(Protocol):
    def post_json(self, url: str, body: dict) -> dict: ...
    def get_json(self, url: str) -> dict: ...


class UrllibHttpClient:
    def __init__(self, timeout: int = 15) -> None:
        self._timeout = timeout

    def post_json(self, url: str, body: dict) -> dict:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 (fixed OSV host)
            return json.loads(resp.read().decode("utf-8"))

    def get_json(self, url: str) -> dict:
        with urllib.request.urlopen(url, timeout=self._timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))


class OsvFeed(AdvisoryFeed):
    def __init__(self, http_client: HttpClient | None = None, *,
                 ecosystem: str = "Debian", base_url: str = OSV_BASE,
                 max_workers: int = _DEFAULT_WORKERS) -> None:
        self._http = http_client or UrllibHttpClient()
        self._ecosystem = ecosystem
        self._base = base_url.rstrip("/")
        self._max_workers = max(1, max_workers)

    def fetch(self, since: datetime | None = None) -> list[Advisory]:
        # OSV is query-by-package, not a global listing.
        return []

    def for_inventory(self, inventory) -> list[Advisory]:
        # Query each host's packages under that host's own OSV ecosystem
        # (detected from /etc/os-release); fall back to the configured default.
        triples = sorted({
            (getattr(hf, "ecosystem", None) or self._ecosystem, name, ver)
            for hf in inventory
            for name, ver in hf.installed_packages.items()
        })
        if not triples:
            return []
        queries = [{"package": {"name": n, "ecosystem": eco}, "version": v}
                   for eco, n, v in triples]

        # OSV caps querybatch at _MAX_BATCH queries, so a fleet scan must be
        # chunked. A failed chunk is skipped (degrade, not abort) so one bad
        # request can't sink the whole report. The same vuln id recurs across
        # packages and rows, so we dedupe to the UNIQUE set before fetching
        # details — the per-vuln GETs are the expensive leg.
        vuln_ids: set[str] = set()
        for start in range(0, len(queries), _MAX_BATCH):
            chunk = queries[start:start + _MAX_BATCH]
            try:
                resp = self._http.post_json(f"{self._base}/v1/querybatch", {"queries": chunk})
            except Exception:  # noqa: BLE001 - skip a failed batch, keep the rest
                continue
            vuln_ids.update(
                v["id"]
                for result in resp.get("results", [])
                for v in result.get("vulns", []) or []
                if v.get("id")
            )
        if not vuln_ids:
            return []
        ordered = sorted(vuln_ids)
        details = self._fetch_details(ordered)

        # Build keyed by canonical CVE; iterate sorted ids so the winner for a
        # given CVE is deterministic regardless of fetch-completion order.
        advisories: dict[str, Advisory] = {}
        for vid in ordered:
            detail = details.get(vid)
            if detail is None:
                continue
            adv = _to_advisory(detail)
            if adv is not None:
                advisories.setdefault(adv.cve_id, adv)
        return list(advisories.values())

    def _fetch_details(self, vuln_ids: list[str]) -> dict[str, dict | None]:
        """Fetch each unique vuln's detail. Parallel (I/O-bound) when there is
        more than one and workers > 1; otherwise serial. A fetch that fails
        yields ``None`` (that advisory is dropped) rather than aborting the whole
        report — a fleet scan issues hundreds of these and must tolerate a
        transient error or rate-limit."""
        def get(vid: str) -> dict | None:
            try:
                return self._http.get_json(f"{self._base}/v1/vulns/{vid}")
            except Exception:  # noqa: BLE001 - degrade: drop one advisory, keep the rest
                return None

        if len(vuln_ids) == 1 or self._max_workers == 1:
            return {vid: get(vid) for vid in vuln_ids}

        out: dict[str, dict | None] = {}
        workers = min(self._max_workers, len(vuln_ids))
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(get, vid): vid for vid in vuln_ids}
            for fut in cf.as_completed(futures):
                out[futures[fut]] = fut.result()
        return out


def _canonical_cve(osv_id: str, aliases: list[str]) -> str:
    """The canonical ``CVE-YYYY-N`` id for an OSV record, so KEV lookup, CVSS,
    and finding de-duplication all key on the same identifier.

    OSV distro feeds use their own ids (``UBUNTU-CVE-2023-1523``, ``USN-...``)
    and carry the CVE as an alias or embedded in the id. Prefer an explicit CVE
    alias, then a CVE embedded in the id, then one embedded in any alias; fall
    back to the OSV id only when no CVE is present at all."""
    for a in aliases:
        if a.startswith("CVE-"):
            return a
    for candidate in (osv_id, *aliases):
        m = _CVE_RE.search(candidate or "")
        if m:
            return m.group(0)
    return osv_id


def _to_advisory(detail: dict) -> Advisory | None:
    osv_id = detail.get("id")
    if not osv_id:
        return None
    aliases = detail.get("aliases", []) or []
    cve_id = _canonical_cve(osv_id, aliases)

    affected: list[AffectedPackage] = []
    for aff in detail.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        name = pkg.get("name")
        if not name:
            continue
        ecosystem = pkg.get("ecosystem", "")
        introduced, fixed = _range_bounds(aff.get("ranges", []) or [])
        affected.append(AffectedPackage(name=name, ecosystem=ecosystem,
                                        fixed_version=fixed, introduced=introduced))

    return Advisory(
        cve_id=cve_id, source="osv", affected=affected,
        cvss=_cvss_score(detail.get("severity", []) or []),
        kev=False,
        published_at=_parse_dt(detail.get("published")),
        metadata={"osv_id": osv_id, "summary": detail.get("summary")},
    )


def _range_bounds(ranges: list) -> tuple[str | None, str | None]:
    introduced: str | None = None
    fixed: str | None = None
    for rng in ranges:
        for event in rng.get("events", []) or []:
            if "introduced" in event and event["introduced"] not in ("0", None):
                introduced = introduced or event["introduced"]
            if "fixed" in event:
                fixed = fixed or event["fixed"]
    return introduced, fixed


def _cvss_score(severity: list) -> float | None:
    # OSV gives a CVSS *vector* (e.g. "CVSS:3.1/AV:N/..."); compute the base
    # score from it. Prefer a v3 vector; also accept a bare number if present.
    from .cvss import base_score_from_vector

    scores = []
    for s in severity:
        val = s.get("score")
        if isinstance(val, str) and val.startswith("CVSS:3"):
            computed = base_score_from_vector(val)
            if computed is not None:
                scores.append(computed)
        else:
            try:
                scores.append(float(val))
            except (TypeError, ValueError):
                continue
    return max(scores) if scores else None


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
