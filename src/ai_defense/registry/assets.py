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
class Asset:
    asset_id: str
    kind: str                 # "ssh-host" | "cloud-account" | ...
    owner: str
    environment: str          # e.g. "web-prod"
    authorization: Authorization


class AssetRegistry:
    def __init__(self) -> None:
        self._assets: dict[str, Asset] = {}

    def register(self, asset: Asset) -> None:
        self._assets[asset.asset_id] = asset

    def require_authorized(self, asset_id: str, now: datetime) -> Asset:
        asset = self._assets.get(asset_id)
        if asset is None:
            raise PermissionError(f"asset not registered: {asset_id}")
        if not asset.authorization.valid(now):
            raise PermissionError(f"authorization invalid/expired: {asset_id}")
        return asset
