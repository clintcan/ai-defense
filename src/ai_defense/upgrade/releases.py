"""Distro release knowledge base — the cited source for upgrade-path decisions.

A small, auditable table of the OS releases this platform understands, their
end-of-life / ESM dates, and the supported in-place upgrade sequence. The
preflight planner reasons only from this table (and read-only host probes); it
never invents a path. Keep it current against the official schedules:

  * Ubuntu release end-of-life:  https://ubuntu.com/about/release-cycle
    (LTS: 5 years standard support, extended to 10+ with Ubuntu Pro / ESM.
     Supported in-place path is LTS -> next LTS, one step at a time, via
     ``do-release-upgrade``.)
  * Debian releases / LTS:       https://wiki.debian.org/DebianReleases
    (Stable upgrades are sequential, one major version at a time.)

Dates are the *end* of the respective support phase (inclusive-ish; treated as
"supported through this date"). ``None`` means not applicable (e.g. a non-LTS
release has no ESM phase).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

SOURCE_REF = ("ubuntu.com/about/release-cycle ; wiki.debian.org/DebianReleases")


@dataclass(frozen=True)
class Release:
    distro: str                 # "ubuntu" | "debian"
    version: str                # "18.04" | "10"
    codename: str               # "bionic" | "buster"
    lts: bool
    standard_eol: date | None   # end of standard/free security support
    esm_eol: date | None = None  # end of extended support (Ubuntu Pro/ESM), if any


# Ordered oldest -> newest. Only releases the platform reasons about.
UBUNTU: list[Release] = [
    Release("ubuntu", "14.04", "trusty", True, date(2019, 4, 30), date(2024, 4, 30)),
    Release("ubuntu", "16.04", "xenial", True, date(2021, 4, 30), date(2026, 4, 30)),
    Release("ubuntu", "18.04", "bionic", True, date(2023, 5, 31), date(2028, 4, 30)),
    Release("ubuntu", "20.04", "focal", True, date(2025, 5, 31), date(2030, 4, 30)),
    Release("ubuntu", "22.04", "jammy", True, date(2027, 6, 30), date(2032, 4, 30)),
    Release("ubuntu", "24.04", "noble", True, date(2029, 6, 30), date(2034, 4, 30)),
]

DEBIAN: list[Release] = [
    Release("debian", "10", "buster", False, date(2024, 6, 30)),
    Release("debian", "11", "bullseye", False, date(2026, 8, 31)),
    Release("debian", "12", "bookworm", False, date(2028, 6, 30)),
    Release("debian", "13", "trixie", False, date(2030, 6, 30)),
]

_SERIES: dict[str, list[Release]] = {"ubuntu": UBUNTU, "debian": DEBIAN}


def _index(series: list[Release], version: str) -> int | None:
    for i, r in enumerate(series):
        if r.version == version:
            return i
    return None


def lookup(distro: str, version: str) -> Release | None:
    series = _SERIES.get((distro or "").lower())
    if series is None:
        return None
    i = _index(series, version)
    return series[i] if i is not None else None


def next_release(distro: str, version: str) -> Release | None:
    """The next supported in-place target after ``version``.

    Ubuntu steps LTS -> next LTS (every entry in UBUNTU is an LTS, so that is
    just the next entry). Debian steps to the next stable. ``None`` if the
    release is unknown or already the newest the table knows."""
    series = _SERIES.get((distro or "").lower())
    if series is None:
        return None
    i = _index(series, version)
    if i is None or i + 1 >= len(series):
        return None
    return series[i + 1]


def path_to_latest(distro: str, version: str) -> list[Release]:
    """Every hop from ``version`` to the newest known release, in order.

    e.g. ubuntu 18.04 -> [20.04, 22.04, 24.04]. Empty if unknown or already
    newest. The first element is the immediate (single-step) target."""
    series = _SERIES.get((distro or "").lower())
    if series is None:
        return []
    i = _index(series, version)
    if i is None:
        return []
    return series[i + 1:]


def support_status(release: Release, on: date) -> str:
    """'supported' | 'esm' | 'eol' for ``release`` as of date ``on``.

    - past ESM end (or past standard end with no ESM phase) -> 'eol'
    - past standard end but within ESM -> 'esm' (security updates need the
      vendor extended programme, e.g. Ubuntu Pro)
    - otherwise 'supported'."""
    if release.standard_eol is None:
        return "supported"
    if on <= release.standard_eol:
        return "supported"
    if release.esm_eol is not None and on <= release.esm_eol:
        return "esm"
    return "eol"
