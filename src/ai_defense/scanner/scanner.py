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


# A static, type-keyed operator hint for the common authenticated-scan failures,
# so a fleet report is self-diagnosing instead of needing a manual investigation
# each sweep. Keyed purely on the exception *class name*: the string is identical
# for every instance of that type and carries no instance data, so — like the
# bare type name — it leaks no host, path, or credential detail into a
# model-visible result.
_SCAN_FAILURE_HINTS: dict[str, str] = {
    "TimeoutError": "host unreachable on the SSH port — check the instance/network firewall",
    "AuthenticationException": "SSH authentication rejected — verify the host's user and key_ref",
    "BadHostKeyException": "host key changed (likely rebuilt) — clear the stale known_hosts entry",
    "NoValidConnectionsError": "no SSH service accepted the connection — verify sshd and the port",
    "ConnectionRefusedError": "connection refused on the SSH port — sshd down or wrong port",
    "SSHException": "SSH negotiation error — inspect the host's SSH service",
    "gaierror": "address did not resolve — check the asset's registry host entry",
}


class HostInspector(Protocol):
    """Collects raw read-only observations for one asset. Implementations MUST
    be side-effect free (query/check-mode only)."""

    def collect(self, asset_id: str) -> dict: ...


class AuthenticatedScanner:
    def __init__(self, inspector: HostInspector) -> None:
        self._inspector = inspector

    @property
    def inspector(self) -> HostInspector:
        return self._inspector

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
        try:
            raw = self._inspector.collect(asset_id)
        except Exception as exc:  # noqa: BLE001 - fail safe: one host must not abort a batch
            return self._failed(asset_id, exc)
        return self._findings(asset_id, raw)

    def scan_hosts(self, asset_ids: list[str]) -> list[HostFindings]:
        return [self.scan_host(a) for a in asset_ids]

    def scan_host_for_upgrade(self, asset_id: str) -> HostFindings:
        """Like ``scan_host`` but also runs the read-only upgrade-eligibility
        probes (``collect_upgrade_state``) when the inspector supports them, so
        the preflight planner can judge readiness. Still strictly non-mutating.
        The extra probes stay off the normal scan path so routine scans stay
        lean.

        A host that cannot be reached/scanned yields a findings record flagged
        ``scan failed`` rather than raising, so one bad host never aborts a fleet
        sweep. The probes are best-effort on top of a successful collect."""
        try:
            raw = dict(self._inspector.collect(asset_id))
        except Exception as exc:  # noqa: BLE001 - fail safe
            return self._failed(asset_id, exc)
        probe = getattr(self._inspector, "collect_upgrade_state", None)
        if callable(probe):
            try:
                raw["system_state"] = {**raw.get("system_state", {}), **(probe(asset_id) or {})}
            except Exception:  # noqa: BLE001 - probes are best-effort, never fatal
                pass
        return self._findings(asset_id, raw)

    @staticmethod
    def _failed(asset_id: str, exc: Exception) -> HostFindings:
        # Record only the exception type, never its message — it can carry host
        # or path detail that must not leak into a model-visible result. Attach a
        # static, type-keyed hint (identical for every instance of the type, so
        # still no instance data) to make the failure actionable in the report.
        kind = type(exc).__name__
        label = f"scan failed: {kind}"
        hint = _SCAN_FAILURE_HINTS.get(kind)
        if hint:
            label = f"{label} — {hint}"
        return HostFindings(asset_id=asset_id, misconfigurations=[label])
