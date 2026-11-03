"""Read-only detection scanner. Feeds observed host state to the vuln planner."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HostFindings:
    asset_id: str
    installed_packages: dict[str, str] = field(default_factory=dict)   # name -> version
    applied_patches: list[str] = field(default_factory=list)
    misconfigurations: list[str] = field(default_factory=list)         # e.g. OVAL fails


class AuthenticatedScanner:
    """TODO: implement using OpenSCAP/OVAL + package-manager query modes and
    read-only cloud patch-state reads (SSM inventory / Azure Update Manager).

    Must only invoke ssh.catalog templates where ``read_only is True``. No
    dry-run/write path is wired into this component by design.
    """

    def scan_host(self, asset_id: str) -> HostFindings:
        raise NotImplementedError
