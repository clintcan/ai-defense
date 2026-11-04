"""OS-upgrade preflight planner (read-only).

Given a host's observed state (from the authenticated scanner), it reports:

  * the current release and its support status (supported / ESM / end-of-life),
  * the supported in-place upgrade target and the full path to the newest
    known release,
  * eligibility *blockers* found by read-only probes (pending reboot, held or
    broken packages, insufficient free disk),
  * a verdict (READY / BLOCKED / CURRENT / UNKNOWN) and advisory notes.

It never dispatches an intent, never mutates a host, and never improvises a path
it cannot cite from the release table. It exists to turn the vuln planner's
"escalate: OS end-of-life" into a concrete, human-verifiable decision; actually
*driving* the upgrade is the separate, strongly-gated ``OS_UPGRADE`` workflow
(``upgrade.workflow`` / the ``os_upgrade`` tool), CLAUDE.md 6c.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import Enum

from ..scanner.scanner import HostFindings
from . import releases
from .releases import Release

# do-release-upgrade needs several GB free; default floor (MB) before we flag it.
DEFAULT_MIN_FREE_MB = 5120


class UpgradeVerdict(str, Enum):
    READY = "ready"            # a supported target exists and no blockers found
    BLOCKED = "blocked"        # a target exists but read-only probes found blockers
    CURRENT = "current"        # already on the newest release the table knows
    UNKNOWN = "unknown"        # OS not detected / not in the release table


@dataclass(frozen=True)
class Blocker:
    code: str
    detail: str


@dataclass(frozen=True)
class OsUpgradeReport:
    asset_id: str
    verdict: UpgradeVerdict
    current_os: str | None            # "ubuntu 18.04 (bionic)"
    support_status: str | None        # supported | esm | eol
    target_version: str | None        # immediate single-step target, e.g. "20.04"
    target_codename: str | None
    distro: str | None = None         # "ubuntu" | "debian" (lowercase, from /etc/os-release ID)
    current_codename: str | None = None   # e.g. "buster" — needed to drive a Debian upgrade
    path: list[str] = field(default_factory=list)      # ["20.04","22.04","24.04"]
    blockers: list[Blocker] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    source_ref: str = releases.SOURCE_REF


class OsUpgradePreflight:
    def __init__(self, *, min_free_mb: int = DEFAULT_MIN_FREE_MB) -> None:
        self._min_free_mb = min_free_mb

    def assess(self, findings: HostFindings, on: date | datetime | None = None) -> OsUpgradeReport:
        today = _as_date(on)
        osr = findings.os_release or {}
        distro = (osr.get("ID") or "").lower()
        version = osr.get("VERSION_ID") or ""

        rel = releases.lookup(distro, version) if distro and version else None
        if rel is None:
            detected = f"{distro or '?'} {version or '?'}".strip()
            return OsUpgradeReport(
                asset_id=findings.asset_id, verdict=UpgradeVerdict.UNKNOWN,
                current_os=detected if detected != "? ?" else None,
                support_status=None, target_version=None, target_codename=None,
                notes=["OS not detected or not in the supported release table; "
                       "cannot determine an upgrade path. Escalate for a human to "
                       "classify this host."],
            )

        current_os = f"{rel.distro} {rel.version} ({rel.codename})"
        status = releases.support_status(rel, today)
        path = [r.version for r in releases.path_to_latest(rel.distro, rel.version)]
        target = releases.next_release(rel.distro, rel.version)
        notes = _status_notes(rel, status)

        if target is None:
            notes.insert(0, f"Already on the newest {rel.distro} release the platform "
                            f"tracks ({rel.version}); no in-place upgrade target.")
            return OsUpgradeReport(
                asset_id=findings.asset_id, verdict=UpgradeVerdict.CURRENT,
                current_os=current_os, support_status=status,
                target_version=None, target_codename=None,
                distro=rel.distro, current_codename=rel.codename, path=[], notes=notes,
            )

        blockers = _blockers(findings.system_state, self._min_free_mb, notes)
        # A retired Debian release's security pool moves to archive.debian.org
        # (bullseye's 404'd on security.debian.org after its 2026-08-31 LTS end),
        # so an in-place hop onto it fails mid-download. Ubuntu is exempt: its
        # upgrader handles EOL hops via old-releases.ubuntu.com.
        if rel.distro == "debian" and releases.support_status(target, today) == "eol":
            blockers.append(Blocker(
                "target_eol",
                f"the single-step target {rel.distro} {target.version} ({target.codename}) "
                f"is itself end of life; its archives are retired, so an in-place hop "
                f"cannot complete. Rebuild on {rel.distro} {path[-1]} and migrate instead."))
        verdict = UpgradeVerdict.BLOCKED if blockers else UpgradeVerdict.READY
        notes.append(f"Supported single-step target is {rel.distro} {target.version} "
                     f"({target.codename}); full path: {' -> '.join(path)}.")
        notes.append("If this host is a cloud-managed image (e.g. AWS Lightsail), the "
                     "vendor may recommend rebuilding from a newer blueprint and "
                     "migrating rather than an in-place release upgrade.")
        notes.append("This is a read-only assessment and makes no change. Driving the "
                     "upgrade (mandatory snapshot, canary->fleet, reboot/reconnect/"
                     "health-recheck, halt-with-restore-point) is the separate "
                     "approval-gated OS_UPGRADE workflow — the `os_upgrade` tool — which "
                     "you invoke explicitly.")
        return OsUpgradeReport(
            asset_id=findings.asset_id, verdict=verdict,
            current_os=current_os, support_status=status,
            target_version=target.version, target_codename=target.codename,
            distro=rel.distro, current_codename=rel.codename,
            path=path, blockers=blockers, notes=notes,
        )

    def assess_all(self, inventory: list[HostFindings],
                   on: date | datetime | None = None) -> list[OsUpgradeReport]:
        return [self.assess(f, on) for f in inventory]


def _status_notes(rel: Release, status: str) -> list[str]:
    if status == "eol":
        return [f"{rel.distro} {rel.version} is END OF LIFE — no security updates even "
                f"with an extended programme. Upgrading is urgent."]
    if status == "esm":
        extra = " (Ubuntu Pro / ESM)" if rel.distro == "ubuntu" else " (vendor extended support)"
        return [f"{rel.distro} {rel.version} is past standard support; security updates "
                f"require the vendor extended programme{extra}. Plan an upgrade."]
    return [f"{rel.distro} {rel.version} is within standard support."]


def _blockers(system_state: dict, min_free_mb: int, notes: list[str]) -> list[Blocker]:
    if not system_state:
        notes.append("Eligibility probes were not collected; readiness is not verified "
                     "(reboot/disk/held/broken packages unchecked).")
        return []

    blockers: list[Blocker] = []
    if system_state.get("reboot_required"):
        blockers.append(Blocker("pending_reboot",
                                "a reboot is pending; clear it before upgrading"))

    held = system_state.get("held_packages") or []
    if held:
        blockers.append(Blocker("held_packages",
                                "held packages will obstruct the upgrade: "
                                + ", ".join(sorted(held))))

    if (system_state.get("broken_packages_report") or "").strip():
        blockers.append(Blocker("broken_packages",
                                "dpkg reports broken/half-configured packages; "
                                "run `dpkg --configure -a` / fix before upgrading"))

    free = system_state.get("disk_free_mb")
    if free is None:
        notes.append("Free disk space could not be determined; verify there is room "
                     f"(>= {min_free_mb} MB) before upgrading.")
    elif free < min_free_mb:
        blockers.append(Blocker("low_disk",
                                f"only {free} MB free on /, need >= {min_free_mb} MB"))
    return blockers


def _as_date(on: date | datetime | None) -> date:
    if on is None:
        return datetime.now(UTC).date()
    if isinstance(on, datetime):
        return on.date()
    return on
