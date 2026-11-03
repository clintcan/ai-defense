"""Bulk onboarding: SSH-user inference, the onboard_instances builder, and the
`bulk-onboard` CLI (dry-run, validation, and real persistence to a DB)."""

import json

from ai_defense.__main__ import main
from ai_defense.db import AssetRepository, init_db
from ai_defense.onboarding import infer_ssh_user, onboard_instances

_INSTANCES = [
    {"service": "lightsail", "name": "web-1", "public_ip": "203.0.113.10",
     "platform": "ubuntu_22_04", "tags": {"env": "prod"}},
    {"service": "lightsail", "name": "db-1", "public_ip": "203.0.113.11",
     "platform": "debian_12", "tags": {}},
    {"service": "ec2", "name": "app-1", "instance_id": "i-1", "private_ip": "10.0.0.5",
     "platform": "Linux/UNIX"},
    {"service": "lightsail", "name": "noip", "platform": "ubuntu_22_04"},  # unreachable
]


class _Reg:
    def __init__(self):
        self.saved = []

    def register(self, asset):
        self.saved.append(asset)


# --- user inference ------------------------------------------------------

def test_infer_ssh_user():
    assert infer_ssh_user("ubuntu_22_04") == "ubuntu"
    assert infer_ssh_user("debian_12") == "admin"
    assert infer_ssh_user("amazon_linux_2") == "ec2-user"
    assert infer_ssh_user("wordpress") == "bitnami"
    assert infer_ssh_user("lamp_8_bitnami") == "bitnami"
    assert infer_ssh_user("nodejs_10_1_0") == "bitnami"   # Lightsail app stack
    assert infer_ssh_user("django_4") == "bitnami"
    assert infer_ssh_user("freebsd_13") == "ubuntu"     # unknown -> default
    assert infer_ssh_user(None) == "ubuntu"


# --- onboard_instances ---------------------------------------------------

def test_onboard_builds_one_asset_per_reachable_instance():
    reg = _Reg()
    res = onboard_instances(
        _INSTANCES, reg.register, owner="ops", granted_by="operator",
        attestation_sig="sig", default_key_ref="ssh-key/default")

    assert len(reg.saved) == 3                           # noip skipped
    assert [s["reason"] for s in res["skipped"]] == ["no public_ip or private_ip"]
    by_id = {a.asset_id: a for a in reg.saved}
    assert by_id["web-1"].connection.user == "ubuntu"
    assert by_id["web-1"].environment == "prod"          # from tag
    assert by_id["db-1"].connection.user == "admin"
    assert by_id["db-1"].environment == "unknown"        # no tag, no override
    assert by_id["app-1"].connection.host == "10.0.0.5"  # fell back to private_ip
    assert by_id["web-1"].connection.key_ref == "ssh-key/default"
    assert by_id["web-1"].kind == "ssh-host"


def test_onboard_environment_override_and_per_host_key():
    reg = _Reg()
    res = onboard_instances(
        _INSTANCES[:2], reg.register, owner="ops", granted_by="op",
        attestation_sig="sig", environment="staging",
        key_ref_by_name={"web-1": "ssh-key/web"})      # no default key

    saved = {a.asset_id: a for a in reg.saved}
    assert set(saved) == {"web-1"}                       # db-1 skipped (no key_ref)
    assert saved["web-1"].connection.key_ref == "ssh-key/web"
    assert saved["web-1"].environment == "staging"       # override applied
    assert res["skipped"][0]["instance"] == "db-1"
    assert "key_ref" in res["skipped"][0]["reason"]


def test_onboard_skips_non_running_instances():
    reg = _Reg()
    insts = [
        {"name": "up", "public_ip": "1.1.1.1", "platform": "ubuntu_22_04", "state": "running"},
        {"name": "down", "public_ip": "2.2.2.2", "platform": "ubuntu_22_04", "state": "stopped"},
    ]
    res = onboard_instances(insts, reg.register, owner="o", granted_by="o",
                            attestation_sig="s", default_key_ref="k")
    assert [a.asset_id for a in reg.saved] == ["up"]
    assert res["skipped"] == [{"instance": "down", "reason": "not running (state=stopped)"}]


def test_onboard_skips_already_registered_unless_update():
    reg = _Reg()
    insts = [{"name": "web-1", "public_ip": "1.1.1.1", "platform": "ubuntu_22_04"}]
    # already registered -> skipped by default
    res = onboard_instances(insts, reg.register, owner="o", granted_by="o",
                            attestation_sig="s", default_key_ref="k",
                            existing_ids={"web-1"})
    assert reg.saved == [] and "already registered" in res["skipped"][0]["reason"]
    # --update overwrites
    res2 = onboard_instances(insts, reg.register, owner="o", granted_by="o",
                             attestation_sig="s", default_key_ref="k",
                             existing_ids={"web-1"}, update=True)
    assert [a.asset_id for a in reg.saved] == ["web-1"] and res2["skipped"] == []


def test_onboard_dry_run_writes_nothing():
    reg = _Reg()
    res = onboard_instances(
        _INSTANCES, reg.register, owner="ops", granted_by="op",
        attestation_sig="sig", default_key_ref="k", dry_run=True)
    assert reg.saved == []                               # nothing registered
    assert len(res["registered"]) == 3 and res["dry_run"] is True


# --- CLI -----------------------------------------------------------------

def _write_instances(tmp_path):
    f = tmp_path / "discovered.json"
    f.write_text(json.dumps({"instances": _INSTANCES}), encoding="utf-8")
    return f


def test_cli_bulk_onboard_dry_run(tmp_path, capsys):
    f = _write_instances(tmp_path)
    rc = main(["bulk-onboard", "--from-json", str(f), "--owner", "ops",
               "--granted-by", "operator", "--attestation-sig", "sig",
               "--key-ref", "ssh-key/default", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "would register 3 host(s)" in out
    assert "dry run" in out


def test_cli_bulk_onboard_requires_input(capsys):
    rc = main(["bulk-onboard", "--owner", "o", "--granted-by", "g",
               "--attestation-sig", "s", "--dry-run"])
    assert rc == 1
    assert "specify an input" in capsys.readouterr().out


def test_cli_bulk_onboard_refuses_write_without_db(tmp_path, capsys):
    f = _write_instances(tmp_path)
    rc = main(["bulk-onboard", "--from-json", str(f), "--owner", "o",
               "--granted-by", "g", "--attestation-sig", "s", "--key-ref", "k"])
    assert rc == 1
    assert "without --db" in capsys.readouterr().out


def test_cli_bulk_onboard_persists_to_db(tmp_path):
    f = _write_instances(tmp_path)
    db = f"sqlite+pysqlite:///{(tmp_path / 'ai.db').as_posix()}"
    rc = main(["bulk-onboard", "--from-json", str(f), "--db", db, "--owner", "ops",
               "--granted-by", "operator", "--attestation-sig", "sig",
               "--key-ref", "ssh-key/default"])
    assert rc == 0
    repo = AssetRepository(init_db(db))
    web = repo.get("web-1")
    assert web is not None and web.kind == "ssh-host"
    assert web.connection.user == "ubuntu" and web.connection.host == "203.0.113.10"
    assert repo.get("noip") is None                      # unreachable one not written
