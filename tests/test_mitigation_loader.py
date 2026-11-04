"""The mitigations folder loader: yaml/json, one-or-many per file, built-in merge,
and — critically — default-deny on any command not in the reviewed catalog."""

import json
from datetime import UTC, datetime, timedelta

from ai_defense.composition import build_demo_engine
from ai_defense.registry.assets import Asset, Authorization, ConnectionInfo
from ai_defense.ssh.catalog import CATALOG, CONFIG_ACTIONS
from ai_defense.vuln.mitigations import load_mitigations

ALLOWED = set(CATALOG) | set(CONFIG_ACTIONS)   # commands + config actions
_OK_T = "harden.disable_pkexec_suid"
_OK_R = "harden.restore_pkexec_suid"


def _mute(_m):      # swallow loader warnings in tests
    pass


def test_builtins_present_without_a_folder():
    reg = load_mitigations(None, allowed_templates=ALLOWED, warn=_mute)
    assert reg.for_cve("CVE-2021-4034").mitigation_id == "pwnkit-pkexec-suid"
    assert reg.command_for("pwnkit-pkexec-suid").template == _OK_T


def test_yaml_single_and_json_multi_per_file(tmp_path):
    (tmp_path / "one.yaml").write_text(
        f"id: foo-mit\ncve: CVE-3000-1\ntitle: Foo\nsource_ref: https://x/CVE-3000-1\n"
        f"template: {_OK_T}\nrollback_template: {_OK_R}\n", encoding="utf-8")
    (tmp_path / "many.json").write_text(json.dumps([
        {"id": "bar-mit", "cves": ["CVE-3000-2", "CVE-3000-3"], "title": "Bar",
         "source_ref": "https://x/CVE-3000-2", "template": _OK_T, "rollback_template": _OK_R},
        {"id": "baz-mit", "cve": "CVE-3000-4", "title": "Baz", "source": "https://x/baz",
         "template": _OK_T, "rollback": _OK_R},
    ]), encoding="utf-8")

    reg = load_mitigations(str(tmp_path), allowed_templates=ALLOWED, warn=_mute)
    assert reg.for_cve("CVE-3000-1").mitigation_id == "foo-mit"          # single-per-file
    assert reg.for_cve("CVE-3000-3").mitigation_id == "bar-mit"          # multi-cve entry
    assert reg.command_for("baz-mit") is not None                       # field aliases work
    assert reg.for_cve("CVE-2021-4034") is not None                     # built-ins still there


def test_rejects_command_not_in_catalog(tmp_path):
    (tmp_path / "evil.yaml").write_text(
        f"id: evil\ncve: CVE-9000-1\ntitle: Evil\nsource_ref: https://x\n"
        f"template: run.anything_i_want\nrollback_template: {_OK_R}\n", encoding="utf-8")
    warns: list[str] = []
    reg = load_mitigations(str(tmp_path), allowed_templates=ALLOWED, warn=warns.append)
    assert reg.for_cve("CVE-9000-1") is None                            # default deny
    assert any("not allowlisted" in w for w in warns)


def test_skips_entry_missing_required_field(tmp_path):
    (tmp_path / "bad.json").write_text(json.dumps(
        {"id": "nosrc", "cve": "CVE-9000-2", "title": "x",
         "template": _OK_T, "rollback_template": _OK_R}), encoding="utf-8")  # no source_ref
    warns: list[str] = []
    reg = load_mitigations(str(tmp_path), allowed_templates=ALLOWED, warn=warns.append)
    assert reg.for_cve("CVE-9000-2") is None
    assert any("source_ref" in w for w in warns)


def test_one_bad_file_does_not_sink_the_rest(tmp_path):
    (tmp_path / "broken.yaml").write_text("}{ not valid yaml :::\n", encoding="utf-8")
    (tmp_path / "good.yaml").write_text(
        f"id: good-mit\ncve: CVE-3000-9\ntitle: Good\nsource_ref: https://x/9\n"
        f"template: {_OK_T}\nrollback_template: {_OK_R}\n", encoding="utf-8")
    warns: list[str] = []
    reg = load_mitigations(str(tmp_path), allowed_templates=ALLOWED, warn=warns.append)
    assert reg.for_cve("CVE-3000-9") is not None      # good one still loaded
    assert any("broken.yaml" in w for w in warns)


def test_folder_overrides_builtin(tmp_path):
    (tmp_path / "override.yaml").write_text(
        f"id: pwnkit-pkexec-suid\ncve: CVE-2021-4034\ntitle: Custom\n"
        f"source_ref: https://internal/wiki/pwnkit\n"
        f"template: {_OK_T}\nrollback_template: {_OK_R}\n", encoding="utf-8")
    reg = load_mitigations(str(tmp_path), allowed_templates=ALLOWED, warn=_mute)
    assert reg.for_cve("CVE-2021-4034").source_ref == "https://internal/wiki/pwnkit"


def test_shipped_mitigations_folder_is_valid():
    # The committed mitigations/ folder must load cleanly: every entry references
    # an allowlisted catalog command (no rejections) — a regression guard against
    # shipping a sample whose command isn't reviewed.
    import os
    folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), "mitigations")
    warns: list[str] = []
    reg = load_mitigations(folder, allowed_templates=ALLOWED, warn=warns.append)
    assert warns == [], warns                              # every shipped file must load
    assert reg.for_cve("CVE-2021-4034") is not None       # pwnkit
    assert reg.for_cve("CVE-2019-11477") is not None       # SACK Panic (multi-CVE)
    assert reg.for_cve("CVE-2019-11479") is not None
    assert reg.for_cve("MPTCP") is not None                # mptcp hardening


def test_engine_mitigate_uses_a_folder_entry(tmp_path):
    # a folder file maps an allowlisted command to a NEW cve -> mitigate offers it
    (tmp_path / "extra.yaml").write_text(
        f"id: pwnkit-pkexec-suid\ncves: [CVE-2021-4034, CVE-2099-9999]\ntitle: PwnKit+\n"
        f"source_ref: https://ubuntu.com/security/CVE-2021-4034\n"
        f"template: {_OK_T}\nrollback_template: {_OK_R}\n", encoding="utf-8")
    eng = build_demo_engine(mitigations_dir=str(tmp_path))
    now = datetime.now(UTC)
    eng.registry.register(Asset(
        "h", "ssh-host", "o", "prod",
        Authorization("s", "o", now - timedelta(minutes=1), now + timedelta(days=90)),
        connection=ConnectionInfo(host="1.1.1.1", key_ref="ssh-key/vps-demo-01", user="ubuntu")))
    res = eng.mitigate("h", "CVE-2099-9999")
    assert res.data.get("approval_state") == "pending"    # folder extended coverage
