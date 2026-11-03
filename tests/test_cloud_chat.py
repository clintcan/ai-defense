"""Full AWS-in-chat slice: live boto3 factory, cloud-account onboarding, and the
cloud engine/MCP tools (exercised against the simulated AWS client, offline)."""

import sys
import types

import pytest

from ai_defense.composition import build_demo_engine
from ai_defense.db import init_db
from ai_defense.mcp_server import handle_call

# --- live boto3 factory (credential normalization, via fake boto3) ------

class _FakeSession:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        _FakeSession.instances.append(self)

    def client(self, name):
        return object()


@pytest.fixture
def fake_boto3(monkeypatch):
    _FakeSession.instances = []
    mod = types.ModuleType("boto3")
    mod.Session = _FakeSession
    monkeypatch.setitem(sys.modules, "boto3", mod)
    return mod


def test_factory_profile_string(fake_boto3):
    from ai_defense.cloud.aws_client import boto3_client_factory
    boto3_client_factory("us-east-1")("secops")             # plain string -> profile
    assert _FakeSession.instances[0].kwargs["profile_name"] == "secops"
    assert _FakeSession.instances[0].kwargs["region_name"] == "us-east-1"


def test_factory_json_string_with_region(fake_boto3):
    from ai_defense.cloud.aws_client import boto3_client_factory
    boto3_client_factory("us-east-1")('{"profile": "dev", "region": "eu-west-1"}')
    assert _FakeSession.instances[0].kwargs["profile_name"] == "dev"
    assert _FakeSession.instances[0].kwargs["region_name"] == "eu-west-1"   # from creds


def test_factory_dict_descriptor(fake_boto3):
    from ai_defense.cloud.aws_client import boto3_client_factory
    boto3_client_factory("us-east-1")({"profile": "ops"})
    assert _FakeSession.instances[0].kwargs["profile_name"] == "ops"


# --- cloud-account onboarding + cloud ops (simulated AWS) ---------------

def _engine():
    # DemoSecretsBackend knows "aws/demo"; use it as the account credential_ref.
    return build_demo_engine(session_factory=init_db())


def _onboard_account(eng, account_id="123456789012"):
    params = dict(account_id=account_id, credential_ref="aws/demo", owner="ops",
                  environment="prod", granted_by="operator")
    pending = handle_call(eng, "onboard_cloud_account", params)
    assert pending["data"]["approval_state"] == "pending"
    eng.approve(pending["data"]["change_set_id"])
    done = handle_call(eng, "onboard_cloud_account", params)
    assert done["ok"]
    return account_id


def test_cloud_account_onboarding_is_approval_gated():
    eng = _engine()
    acct = _onboard_account(eng)
    asset = eng.registry.get(acct)
    assert asset.kind == "cloud-account:aws"
    assert asset.attributes["credential_ref"] == "aws/demo"


def test_cloud_discover_lists_ec2_and_lightsail():
    eng = _engine()
    acct = _onboard_account(eng)
    out = handle_call(eng, "cloud_discover", {"account_id": acct})
    services = {i["service"] for i in out["instances"]}
    assert services == {"ec2", "lightsail"}
    assert not out["errors"]


def test_cloud_patch_state_flags_noncompliant():
    eng = _engine()
    acct = _onboard_account(eng)
    out = handle_call(eng, "cloud_patch_state",
                      {"account_id": acct, "instance_ids": ["i-0demo"]})
    assert out["ok"]
    assert "noncompliant" in out["data"]


def test_cloud_remediate_pending_then_applied():
    eng = _engine()
    acct = _onboard_account(eng)
    pend = handle_call(eng, "cloud_remediate",
                       {"account_id": acct, "instance_ids": ["i-0demo"]})
    assert pend["data"]["approval_state"] == "pending"
    eng.approve(pend["change_set_id"])
    done = handle_call(eng, "cloud_remediate",
                       {"account_id": acct, "instance_ids": ["i-0demo"]})
    assert done["ok"] and done["data"]["command_id"] == "cmd-install"


def test_cloud_ops_require_registered_account():
    eng = _engine()                       # no account onboarded
    out = handle_call(eng, "cloud_discover", {"account_id": "999999999999"})
    assert "error" in out                 # credential ref lookup fails -> error


def test_mcp_manifest_includes_cloud_tools():
    from ai_defense.mcp_server import tool_names
    for t in ("onboard_cloud_account", "cloud_discover", "cloud_patch_state",
              "cloud_remediate"):
        assert t in tool_names()
