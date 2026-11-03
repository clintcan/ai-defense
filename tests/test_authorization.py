"""Unregistered or expired-authorization targets must be refused."""

from datetime import datetime, timedelta

import pytest

from ai_defense.registry.assets import Asset, AssetRegistry, Authorization


def _asset(expired=False):
    now = datetime(2026, 11, 3)
    return Asset(
        asset_id="web-prod-01", kind="ssh-host", owner="t", environment="web-prod",
        authorization=Authorization(
            attestation_sig="sig", granted_by="lead",
            granted_at=now - timedelta(days=1),
            expires_at=now - timedelta(days=1) if expired else now + timedelta(days=30),
        ),
    )


def test_unregistered_rejected():
    reg = AssetRegistry()
    with pytest.raises(PermissionError):
        reg.require_authorized("nope", datetime(2026, 11, 3))


def test_expired_rejected():
    reg = AssetRegistry()
    reg.register(_asset(expired=True))
    with pytest.raises(PermissionError):
        reg.require_authorized("web-prod-01", datetime(2026, 11, 3))


def test_valid_ok():
    reg = AssetRegistry()
    reg.register(_asset())
    assert reg.require_authorized("web-prod-01", datetime(2026, 11, 3))
