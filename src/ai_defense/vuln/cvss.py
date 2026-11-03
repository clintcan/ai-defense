"""CVSS v3.x base-score computation from a vector string.

OSV (and many feeds) give a CVSS *vector* like ``CVSS:3.1/AV:N/AC:L/.../A:H``
rather than a numeric score. This computes the base score per the CVSS v3.1
specification (Appendix A), so advisory prioritization reflects real severity.
CVSS v4 vectors are not handled (return None); callers prefer a v3 vector.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(value: float) -> float:
    # CVSS v3.1 Appendix A roundup (avoids binary float artefacts).
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def base_score_from_vector(vector: str) -> float | None:
    if not vector or not vector.startswith(("CVSS:3.0", "CVSS:3.1")):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        exploitability = (8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
                          * pr_table[metrics["PR"]] * _UI[metrics["UI"]])
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
    except KeyError:
        return None

    if impact <= 0:
        return 0.0
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))
