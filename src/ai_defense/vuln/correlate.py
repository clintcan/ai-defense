"""Correlate advisories against observed host inventory from the scanner.

Matching is on OBSERVED state (what is actually installed), not registry
metadata, so a finding means the package is really present and in the vulnerable
range. Prioritization happens in the planner.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..scanner.scanner import HostFindings
from .feeds import Advisory, is_vulnerable


@dataclass(frozen=True)
class VulnFinding:
    cve_id: str
    asset_id: str
    package: str
    installed_version: str
    fixed_version: str | None        # None => no patch available yet
    ecosystem: str
    advisory: Advisory

    @property
    def patch_available(self) -> bool:
        return self.fixed_version is not None


def correlate_one(advisory: Advisory, host: HostFindings) -> list[VulnFinding]:
    findings: list[VulnFinding] = []
    for pkg in advisory.affected:
        installed = host.installed_packages.get(pkg.name)
        if installed is None:
            continue                     # package not present on this host
        if not is_vulnerable(installed, pkg):
            continue                     # present but already fixed / not in range
        findings.append(VulnFinding(
            cve_id=advisory.cve_id, asset_id=host.asset_id, package=pkg.name,
            installed_version=installed, fixed_version=pkg.fixed_version,
            ecosystem=pkg.ecosystem, advisory=advisory,
        ))
    return findings


def correlate(advisories: list[Advisory], inventory: list[HostFindings]) -> list[VulnFinding]:
    out: list[VulnFinding] = []
    for advisory in advisories:
        for host in inventory:
            out.extend(correlate_one(advisory, host))
    return out
