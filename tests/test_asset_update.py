"""Updating a registered asset's connection info (CLI + gated MCP tool).

A correction — a rotated key_ref, a rebuilt host's new address, a wrong login —
changes only the connection fields and must preserve the asset's authorization
(it is not a re-attestation). Two surfaces, mirroring onboarding: an operator
CLI and an approval-gated tool.
"""

from datetime import UTC, datetime, timedelta

import pytest

from ai_defense.composition import build_demo_engine
from ai_defense.db import init_db
from ai_defense.mcp_server import handle_call
from ai_defense.onboarding import make_asset_update_tool
from ai_defense.registry.assets import (
    Asset,
    AssetRegistry,
    Authorization,
    ConnectionInfo,
)
from ai_defense.toolset.registry import ToolCapability


def _ssh_asset(asset_id="vps-1", *, key_ref="ssh-key/vps-demo-01", **conn) -> Asset:
    now = datetime.now(UTC)
    c = {"host": "1.1.1.1", "key_ref": key_ref, "port": 22, "user": "ubuntu"}
    c.update(conn)
    return Asset(
        asset_id, "ssh-host", "ops", "prod",
        Authorization("sig-abc", "operator", now - timedelta(minutes=1),
                      now + timedelta(days=90)),
        connection=ConnectionInfo(**c),
    )


def _cloud_asset(asset_id="acct") -> Asset:
    now = datetime.now(UTC)
    return Asset(asset_id, "cloud-account:aws", "ops", "prod",
                 Authorization("s", "o", now - timedelta(minutes=1),
                               now + timedelta(days=90)))


# --- in-memory registry -------------------------------------------------

def test_registry_update_connection_preserves_authorization():
    reg = AssetRegistry()
    reg.register(_ssh_asset())
    before = reg.get("vps-1").authorization
    updated = reg.update_connection("vps-1", key_ref="DevKeysPrivate.ppk", user="admin")
    assert updated.connection.key_ref == "DevKeysPrivate.ppk"
    assert updated.connection.user == "admin"
    assert updated.connection.host == "1.1.1.1"       # unspecified field preserved
    assert updated.connection.port == 22
    assert updated.authorization == before            # attestation untouched
    assert reg.get("vps-1").connection.key_ref == "DevKeysPrivate.ppk"


def test_registry_update_connection_errors():
    reg = AssetRegistry()
    with pytest.raises(KeyError):
        reg.update_connection("nope", host="2.2.2.2")
    reg.register(_cloud_asset())                       # no connection -> not updatable
    with pytest.raises(ValueError):
        reg.update_connection("acct", host="2.2.2.2")


# --- DB-backed repository ------------------------------------------------

def test_repo_update_connection_preserves_auth_rows():
    from sqlalchemy import func, select

    from ai_defense.db.models import AuthorizationRow
    from ai_defense.db.repositories import AssetRepository

    sf = init_db()
    repo = AssetRepository(sf)
    repo.save(_ssh_asset("vps-db"))
    repo.update_connection("vps-db", host="9.9.9.9", port=2222)

    a = repo.get("vps-db")
    assert a.connection.host == "9.9.9.9" and a.connection.port == 2222
    assert a.connection.user == "ubuntu"              # preserved
    assert a.authorization.granted_by == "operator"
    # the correction must NOT append an authorization row (unlike save()).
    with sf() as s:
        n = s.scalar(select(func.count()).select_from(AuthorizationRow)
                     .where(AuthorizationRow.asset_id == "vps-db"))
    assert n == 1


def test_repo_update_connection_unknown_and_non_ssh():
    from ai_defense.db.repositories import AssetRepository

    repo = AssetRepository(init_db())
    with pytest.raises(KeyError):
        repo.update_connection("ghost", host="1.2.3.4")
    repo.save(_cloud_asset("acct-db"))
    with pytest.raises(ValueError):
        repo.update_connection("acct-db", host="1.2.3.4")


# --- gated tool executor (unit) -----------------------------------------

def test_update_tool_executor_paths():
    reg = AssetRegistry()
    reg.register(_ssh_asset("vps-1"))
    spec = make_asset_update_tool(reg.update_connection)
    assert spec.capability is ToolCapability.MUTATING

    ok = spec.executor({"asset_id": "vps-1", "user": "admin"},
                       resolve_secret=lambda ref: "KEYDATA")
    assert ok.ok and ok.data["user"] == "admin" and ok.data["changed"] == ["user"]

    none = spec.executor({"asset_id": "vps-1"}, resolve_secret=lambda ref: "KEYDATA")
    assert not none.ok and "no connection fields" in none.summary

    missing = spec.executor({"asset_id": "vps-1", "key_ref": "absent"},
                            resolve_secret=lambda ref: None)   # not in vault
    assert not missing.ok and "key_ref not found" in missing.summary

    ghost = spec.executor({"asset_id": "ghost", "user": "x"},
                          resolve_secret=lambda ref: "KEYDATA")
    assert not ghost.ok                                # update_fn raised -> ok=False


# --- engine (approval-gated) --------------------------------------------

def test_engine_update_is_approval_gated_then_applies():
    eng = build_demo_engine()
    eng.registry.register(_ssh_asset("vps-1"))

    pending = eng.update_asset_connection("vps-1", user="admin", port=2222)
    assert not pending.ok and pending.data["approval_state"] == "pending"
    assert eng.registry.get("vps-1").connection.user == "ubuntu"    # not applied yet

    eng.approve(pending.data["change_set_id"])
    done = eng.update_asset_connection("vps-1", user="admin", port=2222)
    assert done.ok
    a = eng.registry.get("vps-1")
    assert a.connection.user == "admin" and a.connection.port == 2222
    assert a.authorization.granted_by == "operator"                # attestation preserved


def test_engine_update_rejects_bad_input_before_dispatch():
    eng = build_demo_engine()
    # control-plane is seeded but has no connection -> not updatable
    no_fields = eng.update_asset_connection("control-plane")
    assert not no_fields.ok and "no connection fields" in no_fields.summary
    not_ssh = eng.update_asset_connection("control-plane", user="x")
    assert not not_ssh.ok and "not an updatable ssh-host" in not_ssh.summary
    unknown = eng.update_asset_connection("ghost", host="1.2.3.4")
    assert not unknown.ok and "not an updatable ssh-host" in unknown.summary


def test_engine_update_denied_for_expired_authorization():
    eng = build_demo_engine()
    now = datetime.now(UTC)
    eng.registry.register(Asset(
        "vps-old", "ssh-host", "ops", "prod",
        Authorization("s", "o", now - timedelta(days=200), now - timedelta(days=100)),
        connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01")))
    res = eng.update_asset_connection("vps-old", user="x")
    assert not res.ok and "authoriz" in res.summary.lower()        # dispatcher step 2


# --- MCP handler ---------------------------------------------------------

def test_mcp_update_asset_pending_then_applies():
    eng = build_demo_engine()
    eng.registry.register(_ssh_asset("vps-1"))
    args = {"asset_id": "vps-1", "key_ref": "ssh-key/vps-demo-01", "user": "admin"}

    out = handle_call(eng, "update_asset", args)
    assert out["ok"] is False and out.get("change_set_id")
    handle_call(eng, "approve_change", {"change_set_id": out["change_set_id"]})
    out2 = handle_call(eng, "update_asset", args)
    assert out2["ok"] is True
    assert eng.registry.get("vps-1").connection.user == "admin"


def test_mcp_update_asset_no_fields_errors():
    eng = build_demo_engine()
    eng.registry.register(_ssh_asset("vps-1"))
    out = handle_call(eng, "update_asset", {"asset_id": "vps-1"})
    assert out["ok"] is False and "no connection fields" in out["summary"]


# --- operator CLI --------------------------------------------------------

def test_cli_update_asset(tmp_path):
    from ai_defense.__main__ import main
    from ai_defense.db.repositories import AssetRepository

    db_url = f"sqlite+pysqlite:///{(tmp_path / 'cli.db').as_posix()}"
    AssetRepository(init_db(db_url)).save(_ssh_asset("vps-cli"))

    rc = main(["update-asset", "--db", db_url, "--asset-id", "vps-cli",
               "--key-ref", "DevKeysPrivate.ppk", "--user", "admin"])
    assert rc == 0
    a = AssetRepository(init_db(db_url)).get("vps-cli")
    assert a.connection.key_ref == "DevKeysPrivate.ppk" and a.connection.user == "admin"
    assert a.connection.host == "1.1.1.1"             # untouched

    assert main(["update-asset", "--db", db_url, "--asset-id", "vps-cli"]) == 1  # no fields
