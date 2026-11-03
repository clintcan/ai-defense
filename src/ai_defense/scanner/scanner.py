"""Read-only detection scanner. Feeds observed host state to the vuln planner.

The scanner depends on an injected ``HostInspector`` that returns raw observed
data for an asset. The production inspector runs only read-only catalog commands
(package-manager query modes, OpenSCAP/OVAL) over SSH, or reads cloud patch
state; a fake inspector backs tests. By construction there is no dry-run or write
path here: the scanner detects and reports, it never changes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class HostFindings:
    asset_id: str
    installed_packages: dict[str, str] = field(default_factory=dict)   # name -> version
    applied_patches: list[str] = field(default_factory=list)
    misconfigurations: list[str] = field(default_factory=list)         # e.g. OVAL fails
    ecosystem: str | None = None   # OSV distro ecosystem for this host, e.g. "Ubuntu:22.04:LTS"
    os_release: dict[str, str] = field(default_factory=dict)   # parsed /etc/os-release
    # Read-only upgrade-eligibility probes (reboot pending, free disk, held/broken
    # packages). Populated only on the preflight path; empty on a normal scan.
    system_state: dict = field(default_factory=dict)


class HostInspector(Protocol):
    """Collects raw read-only observations for one asset. Implementations MUST
    be side-effect free (query/check-mode only)."""

    def collect(self, asset_id: str) -> dict: ...


class AuthenticatedScanner:
    def __init__(self, inspector: HostInspector) -> None:
        self._inspector = inspector

    def _findings(self, asset_id: str, raw: dict) -> HostFindings:
        return HostFindings(
            asset_id=asset_id,
            installed_packages=dict(raw.get("installed_packages", {})),
            applied_patches=list(raw.get("applied_patches", [])),
            misconfigurations=list(raw.get("misconfigurations", [])),
            ecosystem=raw.get("ecosystem"),
            os_release=dict(raw.get("os_release", {})),
            system_state=dict(raw.get("system_state", {})),
        )

    def scan_host(self, asset_id: str) -> HostFindings:
        return self._findings(asset_id, self._inspector.collect(asset_id))

    def scan_hosts(self, asset_ids: list[str]) -> list[HostFindings]:
        return [self.scan_host(a) for a in asset_ids]

    def scan_host_for_upgrade(self, asset_id: str) -> HostFindings:
        """Like ``scan_host`` but also runs the read-only upgrade-eligibility
        probes (``collect_upgrade_state``) when the inspector supports them, so
        the preflight planner can judge readiness. Still strictly non-mutating.
        The extra probes stay off the normal scan path so routine scans stay
        lean."""
        raw = dict(self._inspector.collect(asset_id))
        probe = getattr(self._inspector, "collect_upgrade_state", None)
        if callable(probe):
            raw["system_state"] = {**raw.get("system_state", {}), **(probe(asset_id) or {})}
        return self._findings(asset_id, raw)
