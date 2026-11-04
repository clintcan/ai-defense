"""Credential/provider resolution for the patch- and OS-upgrade snapshot steps.

An ssh-host asset carries no link to its own cloud account or instance type
(host/port/user/key_ref only), so RemediationWorkflow/OsUpgradeWorkflow need
somewhere else to get a credential_ref and a provider ("ec2"/"lightsail") for the
pre-change snapshot. ``_snapshot_workflow_defaults`` auto-detects from the
registry when it can (exactly one cloud account registered — this fleet's shape)
and falls back to the long-standing demo default otherwise, so no existing
demo-engine test is affected."""

from datetime import UTC, datetime, timedelta

from ai_defense.cloud.tools import SNAPSHOT_TOOL
from ai_defense.composition import _snapshot_workflow_defaults, build_demo_engine, build_engine
from ai_defense.registry.assets import Asset, Authorization


def _cloud_account(asset_id="111111111111", credential_ref="aws/example") -> Asset:
    now = datetime.now(UTC)
    return Asset(asset_id, "cloud-account:aws", "example-owner", "prod",
                 Authorization("s", "o", now - timedelta(minutes=1), now + timedelta(days=90)),
                 attributes={"credential_ref": credential_ref, "provider": "aws"})


def test_no_cloud_account_falls_back_to_demo_default():
    eng = build_demo_engine()      # only the control-plane asset is registered
    cred_for, service_for = _snapshot_workflow_defaults(
        eng.registry, default_cloud_account=None, default_cloud_service=None)
    assert cred_for("any-host") == "aws/demo" and service_for("any-host") == "ec2"


def test_single_cloud_account_auto_resolves_real_credential_and_lightsail():
    eng = build_demo_engine()
    eng.registry.register(_cloud_account())
    cred_for, service_for = _snapshot_workflow_defaults(
        eng.registry, default_cloud_account=None, default_cloud_service=None)
    assert cred_for("db-proxy-1") == "aws/example"      # the real account's ref, not aws/demo
    assert service_for("db-proxy-1") == "lightsail"


def test_multiple_cloud_accounts_is_ambiguous_falls_back_to_demo_default():
    eng = build_demo_engine()
    eng.registry.register(_cloud_account("111111111111", "aws/one"))
    eng.registry.register(_cloud_account("222222222222", "aws/two"))
    cred_for, service_for = _snapshot_workflow_defaults(
        eng.registry, default_cloud_account=None, default_cloud_service=None)
    assert cred_for("any-host") == "aws/demo" and service_for("any-host") == "ec2"


def test_explicit_override_wins_over_auto_detection():
    eng = build_demo_engine()
    eng.registry.register(_cloud_account("111111111111", "aws/one"))
    eng.registry.register(_cloud_account("222222222222", "aws/two"))
    cred_for, service_for = _snapshot_workflow_defaults(
        eng.registry, default_cloud_account="222222222222", default_cloud_service="ec2")
    assert cred_for("any-host") == "aws/two" and service_for("any-host") == "ec2"


def test_engine_workflows_use_the_resolved_credential_and_service():
    # end-to-end, mirroring production: the cloud account is onboarded once, then
    # the engine is (re)built on a restart/reconnect — exactly when a FRESH
    # OsUpgradeWorkflow resolves credential_ref_for/service_for, same as
    # test_durable_engine.py's "survives a fresh engine" pattern.
    from ai_defense.db import init_db
    from ai_defense.toolset.intents import ActionClass, Intent

    sf = init_db()
    eng1 = build_engine(session_factory=sf)
    eng1.registry.register(_cloud_account())

    eng2 = build_engine(session_factory=sf)          # fresh build, same DB (a restart)
    intent = eng2.os_workflow._snapshot_intent("db-proxy-1")
    assert isinstance(intent, Intent) and intent.tool == SNAPSHOT_TOOL
    assert intent.action_class == ActionClass.PROTECTIVE
    assert intent.params["credential_ref"] == "aws/example"
    assert intent.params["service"] == "lightsail"
