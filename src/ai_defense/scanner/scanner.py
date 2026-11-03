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


class HostInspector(Protocol):
    """Collects raw read-only observations for one asset. Implementations MUST
    be side-effect free (query/check-mode only)."""

    def collect(self, asset_id: str) -> dict: ...


class AuthenticatedScanner:
    def __init__(self, inspector: HostInspector) -> None:
        self._inspector = inspector

    def scan_host(self, asset_id: str) -> HostFindings:
        raw = self._inspector.collect(asset_id)
        return HostFindings(
            asset_id=asset_id,
            installed_packages=dict(raw.get("installed_packages", {})),
            applied_patches=list(raw.get("applied_patches", [])),
            misconfigurations=list(raw.get("misconfigurations", [])),
        )

    def scan_hosts(self, asset_ids: list[str]) -> list[HostFindings]:
        return [self.scan_host(a) for a in asset_ids]
