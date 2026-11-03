"""Advisory feeds: NVD/CVE, vendor advisories, OSV, distro trackers, CISA KEV."""

from __future__ import annotations

from abc import ABC, abstractmethod


class AdvisoryFeed(ABC):
    @abstractmethod
    def fetch(self, since: str | None = None) -> list[dict]:
        """Return advisories. TODO: per-source clients + normalization."""
