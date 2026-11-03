"""CVSS v3 base-score computation + OSV severity parsing."""

from ai_defense.vuln.cvss import base_score_from_vector
from ai_defense.vuln.osv import _cvss_score


def test_known_vectors():
    # classic 9.8 critical (RCE, no auth, no UI, scope unchanged, C/I/A high)
    assert base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    # scope-changed medium (matches NVD for CVE-2020-13596)
    assert base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    # a low one
    assert base_score_from_vector("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") < 3.0
    # none-impact -> 0.0
    assert base_score_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_v30_prefix_supported():
    assert base_score_from_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_non_v3_or_garbage_returns_none():
    assert base_score_from_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N") is None
    assert base_score_from_vector("not-a-vector") is None
    assert base_score_from_vector("") is None


def test_osv_cvss_score_parses_vector():
    sev = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
           {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N"}]
    assert _cvss_score(sev) == 9.8          # uses the v3 vector, ignores v4


def test_osv_cvss_score_none_when_absent():
    assert _cvss_score([]) is None
    assert _cvss_score([{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]) is None
