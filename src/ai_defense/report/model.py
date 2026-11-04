"""Canonical report model — the format-independent intermediate representation.

Every renderer (markdown, generic JSON, DefectDojo) consumes this. Building the
model once and serializing many ways keeps the renderers thin and the data
consistent across them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SCHEMA_VERSION = "1.0"


def severity_for(cvss: float | None) -> str:
    """CVSS v3 qualitative severity band. ``None`` -> 'Unknown' (so a missing
    score is never silently treated as low risk)."""
    if cvss is None:
        return "Unknown"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    if cvss > 0.0:
        return "Low"
    return "Info"


@dataclass(frozen=True)
class ReportFinding:
    cve_id: str
    package: str
    kind: str                      # patch | mitigation | escalate
    severity: str                  # Critical/High/Medium/Low/Info/Unknown
    cvss: float | None
    kev: bool
    installed_version: str | None
    fixed_version: str | None
    priority: float
    source_ref: str
    note: str
    requires_human: bool
    unique_id: str                 # stable across re-scans: asset:cve:package

    @property
    def reference_url(self) -> str | None:
        """A URL a human can open to verify the finding (CLAUDE.md rule #6)."""
        cve = self.cve_id
        if cve.startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{cve}"
        if cve.startswith("UBUNTU-CVE-") or cve.startswith("USN-"):
            return f"https://ubuntu.com/security/{cve}"
        return None


@dataclass(frozen=True)
class ReportAsset:
    asset_id: str
    host: str | None = None               # connection address (IP/FQDN) from the registry
    port: int | None = None
    os: str | None = None                 # "ubuntu 18.04 (bionic)"
    ecosystem: str | None = None          # OSV ecosystem
    support_status: str | None = None     # supported | esm | eol (from preflight)
    upgrade_verdict: str | None = None    # ready | blocked | current | unknown
    upgrade_target: str | None = None     # next release, e.g. "20.04"
    upgrade_path: list[str] = field(default_factory=list)
    findings: list[ReportFinding] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)   # scan problems (e.g. "scan failed: ...")
    scan_exempt: bool = False              # intentionally not SSH-scanned (by configuration)
    exempt_reason: str | None = None       # why it is exempt (operator note)

    @property
    def scanned(self) -> bool:
        """Genuinely scanned this run — neither exempt nor a scan failure."""
        return not self.scan_exempt and not any(i.startswith("scan failed") for i in self.issues)

    @property
    def failed(self) -> bool:
        """A *real* scan failure (unreachable/auth/host-key), not a deliberate
        exemption — so an off-limits host is never counted as a failure."""
        return not self.scan_exempt and any(i.startswith("scan failed") for i in self.issues)


@dataclass(frozen=True)
class ReportProvenance:
    generated_at: datetime
    scope: list[str]                      # asset ids assessed
    advisory_source: str                  # "osv.dev" | feed class name
    kev_enabled: bool
    scan_mode: str = "authenticated"      # authenticated host scan vs. simulated
    tool: str = "ai-defense"
    schema_version: str = SCHEMA_VERSION
    feed_degraded: bool = False           # advisory fetch was incomplete this run
    feed_note: str | None = None          # how it degraded (for the report banner)


@dataclass(frozen=True)
class Report:
    provenance: ReportProvenance
    assets: list[ReportAsset]
    audit_verified: bool | None = None    # tamper-evident chain verified at gen time

    # -- aggregates (computed, used by every renderer) --------------------
    @property
    def all_findings(self) -> list[ReportFinding]:
        return [f for a in self.assets for f in a.findings]

    @property
    def kev_findings(self) -> list[ReportFinding]:
        return [f for f in self.all_findings if f.kev]

    def counts_by_kind(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.all_findings:
            out[f.kind] = out.get(f.kind, 0) + 1
        return out

    def counts_by_severity(self) -> dict[str, int]:
        order = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
        out = {k: 0 for k in order}
        for f in self.all_findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return {k: v for k, v in out.items() if v}

    @property
    def eol_assets(self) -> list[ReportAsset]:
        return [a for a in self.assets if a.support_status in ("esm", "eol")]

    @property
    def failed_assets(self) -> list[ReportAsset]:
        return [a for a in self.assets if a.failed]

    @property
    def exempt_assets(self) -> list[ReportAsset]:
        return [a for a in self.assets if a.scan_exempt]
