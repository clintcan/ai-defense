"""Base cloud adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CloudAdapter(ABC):
    """Each concrete adapter wraps ONLY the reviewed, allowlisted operations."""

    provider: str

    # --- read-only -------------------------------------------------------
    @abstractmethod
    def list_instances(self, account: str, filters: dict) -> list[dict]: ...

    @abstractmethod
    def describe_patch_state(self, instance_ids: list[str]) -> list[dict]: ...

    # --- protective ------------------------------------------------------
    @abstractmethod
    def snapshot_before_change(self, instance_id: str) -> dict: ...

    # --- write (approval-gated) -----------------------------------------
    @abstractmethod
    def apply_patch_baseline(self, instance_ids: list[str], baseline: str) -> dict: ...

    @abstractmethod
    def blast_radius(self, op: str, params: dict[str, Any]) -> int:
        """How many assets this op would affect — surfaced to policy & approver."""
