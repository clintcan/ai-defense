"""Managed-asset inventory and the authorization ledger."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Authorization:
    """Signed, timestamped attestation that we may administer an asset."""

    attestation_sig: str
    granted_by: str
    granted_at: datetime
    expires_at: datetime

    def valid(self, now: datetime) -> bool:
        return self.granted_at <= now < self.expires_at


@dataclass(frozen=True)
class ConnectionInfo:
    """How to reach an ``ssh-host`` asset. ``key_ref`` points at the SSH key in
    the vault — the key itself is never stored here (or anywhere the planner can
    see). Resolved from the trusted registry, not from planner-supplied text, so
    a command can never be aimed at an arbitrary host."""

    host: str                 # IP or DNS name
    key_ref: str              # vault reference to the private key / certificate
    port: int = 22
    user: str = "root"


@dataclass(frozen=True)
class Asset:
    asset_id: str
    kind: str                 # "ssh-host" | "cloud-account" | "control-plane" | ...
    owner: str
    environment: str          # e.g. "web-prod"
    authorization: Authorization
    connection: ConnectionInfo | None = None   # for ssh-host assets


class AssetRegistry:
    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}

    def register(self, asset: Asset) -> None:
        self._assets[asset.asset_id] = asset

    def get(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def all(self) -> list[Asset]:
        return list(self._assets.values())

    def require_authorized(self, asset_id: str, now: datetime) -> Asset:
        return _require_authorized(self.get(asset_id), asset_id, now)


def _require_authorized(asset: Asset | None, asset_id: str, now: datetime) -> Asset:
    """Shared authorization check for any registry (in-memory or DB-backed)."""
    if asset is None:
        raise PermissionError(f"asset not registered: {asset_id}")
    if not asset.authorization.valid(now):
        raise PermissionError(f"authorization invalid/expired: {asset_id}")
    return asset
