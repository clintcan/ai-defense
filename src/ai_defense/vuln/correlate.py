"""Correlate advisories against observed host inventory from the scanner."""

from __future__ import annotations

from ..scanner.scanner import HostFindings


def affected_hosts(advisory: dict, inventory: list[HostFindings]) -> list[str]:
    """Return asset_ids affected by an advisory, based on OBSERVED state.

    TODO: match package/version ranges and config predicates from the advisory
    against each host's findings. Prioritization (KEV + CVSS + exposure +
    exploit availability) happens in the planner.
    """
    raise NotImplementedError
