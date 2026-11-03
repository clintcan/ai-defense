"""Credential-selection logic of Boto3AwsClient, covered by injecting a fake
boto3 module (so the real SDK/network is not required)."""

import sys
import types

import pytest

from ai_defense.cloud.aws_client import Boto3AwsClient


class _FakeStsClient:
    def assume_role(self, **kwargs):
        _FakeSession.last_assume_role = kwargs
        return {"Credentials": {
            "AccessKeyId": "ASIA-TEMP", "SecretAccessKey": "temp-secret",
            "SessionToken": "temp-token",
        }}


class _FakeSession:
    instances: list = []
    last_assume_role: dict | None = None

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.clients: list[str] = []
        _FakeSession.instances.append(self)

    def client(self, name):
        self.clients.append(name)
        return _FakeStsClient() if name == "sts" else object()


@pytest.fixture
def fake_boto3(monkeypatch):
    _FakeSession.instances = []
    _FakeSession.last_assume_role = None
    mod = types.ModuleType("boto3")
    mod.Session = _FakeSession
    monkeypatch.setitem(sys.modules, "boto3", mod)
    return mod


def test_profile_mode_uses_named_profile(fake_boto3):
    Boto3AwsClient({"profile": "secops"}, region="us-east-1")
    sess = _FakeSession.instances[-1]
    assert sess.kwargs == {"profile_name": "secops", "region_name": "us-east-1"}
    assert sess.clients == ["ec2", "ssm", "lightsail"]


def test_default_chain_when_no_descriptor(fake_boto3):
    # {} -> default provider chain (instance role / env / SSO), like the CLI.
    Boto3AwsClient({}, region="eu-west-1")
    sess = _FakeSession.instances[-1]
    assert sess.kwargs == {"region_name": "eu-west-1"}
    assert "aws_access_key_id" not in sess.kwargs
    assert "profile_name" not in sess.kwargs


def test_none_descriptor_also_default_chain(fake_boto3):
    Boto3AwsClient(region=None)
    assert _FakeSession.instances[-1].kwargs == {"region_name": None}


def test_static_keys_mode(fake_boto3):
    Boto3AwsClient(
        {"aws_access_key_id": "AKIA-X", "aws_secret_access_key": "y", "aws_session_token": "z"},
        region="us-east-2",
    )
    sess = _FakeSession.instances[-1]
    assert sess.kwargs["aws_access_key_id"] == "AKIA-X"
    assert sess.kwargs["aws_session_token"] == "z"


def test_assume_role_layers_on_profile_base(fake_boto3):
    Boto3AwsClient({"profile": "sso-dev", "role_arn": "arn:aws:iam::1:role/discovery"},
                   region="us-east-1")
    # base session built from the profile, then STS assume_role, then a new
    # session from the temporary credentials.
    base, final = _FakeSession.instances[0], _FakeSession.instances[-1]
    assert base.kwargs["profile_name"] == "sso-dev"
    assert "sts" in base.clients
    assert _FakeSession.last_assume_role["RoleArn"] == "arn:aws:iam::1:role/discovery"
    assert final.kwargs["aws_access_key_id"] == "ASIA-TEMP"
    assert final.clients == ["ec2", "ssm", "lightsail"]
