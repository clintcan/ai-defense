"""A small set of demo advisories for the local demo run.

Real deployments load these from live feeds (OSV/NVD/vendor/CISA KEV) behind the
``AdvisoryFeed`` seam; these fixed entries let the demo run offline.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .vuln.feeds import Advisory, AffectedPackage

DEMO_ADVISORIES: list[Advisory] = [
    Advisory(
        cve_id="CVE-2026-1001", source="osv",
        affected=[AffectedPackage("openssl", fixed_version="3.0.8", introduced="3.0.0")],
        cvss=7.5, kev=True,
        published_at=datetime(2026, 10, 1, tzinfo=UTC),
    ),
    Advisory(
        cve_id="CVE-2026-1002", source="vendor",
        affected=[AffectedPackage("bash", fixed_version=None, introduced="5.0")],
        cvss=6.1, kev=False,
        mitigation="restrict shell access; disable the affected feature in /etc/profile",
        published_at=datetime(2026, 10, 15, tzinfo=UTC),
    ),
]
