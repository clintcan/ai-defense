"""Advisory feeds and the normalized Advisory model.

Real sources (NVD/CVE, OSV, distro trackers, CISA KEV) plug in behind
``AdvisoryFeed``; a ``StaticAdvisoryFeed`` backs tests and fixtures. All feeds
yield the same normalized ``Advisory`` so correlation and planning are
source-agnostic.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class AffectedPackage:
    """One vulnerable package and the version boundary that fixes it.

    ``fixed_version`` is the first non-vulnerable version; if ``None`` there is no
    patch yet (a mitigation, if any, lives on the Advisory). ``introduced`` is the
    first affected version (defaults to "all earlier").
    """

    name: str
    ecosystem: str = "debian"            # debian | rpm | pypi | npm | ...
    fixed_version: str | None = None
    introduced: str | None = None


@dataclass(frozen=True)
class Advisory:
    cve_id: str
    source: str
    affected: list[AffectedPackage]
    cvss: float | None = None
    kev: bool = False                    # CISA Known Exploited Vulnerabilities
    mitigation: str | None = None        # published workaround when no patch
    published_at: datetime | None = None
    metadata: dict = field(default_factory=dict)

    def patch_available(self, package: str) -> bool:
        return any(a.name == package and a.fixed_version for a in self.affected)


class AdvisoryFeed(ABC):
    @abstractmethod
    def fetch(self, since: datetime | None = None) -> list[Advisory]:
        """Return normalized advisories (optionally only those after ``since``)."""


class StaticAdvisoryFeed(AdvisoryFeed):
    """In-memory feed for fixtures/tests and for pinned advisory sets."""

    def __init__(self, advisories: list[Advisory]) -> None:
        self._advisories = list(advisories)

    def fetch(self, since: datetime | None = None) -> list[Advisory]:
        if since is None:
            return list(self._advisories)
        return [a for a in self._advisories
                if a.published_at is None or a.published_at >= since]


class CompositeFeed(AdvisoryFeed):
    """Merge several feeds; later feeds do not override earlier, all are returned."""

    def __init__(self, feeds: list[AdvisoryFeed]) -> None:
        self._feeds = list(feeds)

    def fetch(self, since: datetime | None = None) -> list[Advisory]:
        out: list[Advisory] = []
        for f in self._feeds:
            out.extend(f.fetch(since))
        return out


# --- version comparison --------------------------------------------------
#
# A pragmatic, ecosystem-agnostic comparator good enough for correlation in this
# scaffold. Production code should use per-ecosystem comparators (dpkg, rpm,
# PEP 440, semver) — see _COMPARATORS as the extension point.

_SPLIT = re.compile(r"[.\-+~:]")


def _parse(version: str) -> list:
    parts: list = []
    for chunk in _SPLIT.split(version.strip()):
        # split each chunk into runs of digits / non-digits for mixed tokens
        for token in re.findall(r"\d+|[A-Za-z]+", chunk):
            parts.append(int(token) if token.isdigit() else token)
    return parts


def version_lt(a: str, b: str) -> bool:
    """True if version ``a`` is strictly less than ``b`` (best-effort)."""
    pa, pb = _parse(a), _parse(b)
    for x, y in zip(pa, pb):
        if x == y:
            continue
        # numbers sort below only against numbers; a numeric component outranks
        # an alphabetic one (e.g. 1.0 > 1.0rc1-style handled loosely).
        if isinstance(x, int) and isinstance(y, int):
            return x < y
        if isinstance(x, int) != isinstance(y, int):
            return isinstance(y, int)      # alpha < numeric
        return str(x) < str(y)
    return len(pa) < len(pb)


def is_vulnerable(installed: str, affected: AffectedPackage) -> bool:
    """Is ``installed`` within the vulnerable range of ``affected``?

    - below ``introduced`` (if given) -> not affected
    - at/above ``fixed_version`` (if given) -> fixed, not affected
    - otherwise vulnerable. With no ``fixed_version`` (no patch), any version
      at/above ``introduced`` is considered vulnerable.
    """
    if affected.introduced and version_lt(installed, affected.introduced):
        return False
    if affected.fixed_version and not version_lt(installed, affected.fixed_version):
        return False
    return True
