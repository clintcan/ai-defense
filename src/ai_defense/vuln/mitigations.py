"""Known, cited CVE mitigations — a published workaround to apply when the vendor
patch cannot be (an EOL OS without ESM, or a fix not yet shipped).

Like the upgrade release table, this is an **auditable source**: the engine never
invents a mitigation, it only offers one listed here, each citing the advisory a
human can verify against (CLAUDE.md hard rule #6). The actual command is an
**allowlisted, reversible** template in the SSH toolset (``ssh/tools.py``); this
table only names which mitigation applies to a CVE and where it's documented, so
advisory knowledge (here) and command selection (the toolset) stay separate.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Mitigation:
    mitigation_id: str        # links to the allowlisted command in the SSH toolset
    cve_id: str
    title: str                # human summary of the workaround
    source_ref: str           # advisory URL a human can verify (rule #6)
    temporary: bool = True     # a mitigation is a stopgap until the real patch lands


KNOWN_MITIGATIONS: dict[str, Mitigation] = {
    # PwnKit: strip the setuid bit from pkexec so an unprivileged user can no
    # longer use the argv overflow to gain root. The vendor fix is still
    # preferred where it installs; this neutralizes the exploit where it can't.
    "CVE-2021-4034": Mitigation(
        mitigation_id="pwnkit-pkexec-suid",
        cve_id="CVE-2021-4034",
        title="Remove the setuid bit from /usr/bin/pkexec (PwnKit workaround)",
        source_ref="https://ubuntu.com/security/CVE-2021-4034",
    ),
}


def mitigation_for(cve_id: str) -> Mitigation | None:
    """The published mitigation for a CVE, or ``None`` if none is catalogued
    (then it must escalate to a human — never improvise)."""
    return KNOWN_MITIGATIONS.get(cve_id)
