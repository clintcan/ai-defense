"""Allowlisted hardening/mitigation *commands* — fixed argv, reversible.

These are one-shot catalog commands that CVE mitigations (``vuln/mitigations.py``)
reference. Distinct from ``ai_defense.ssh.hardening``, which holds the managed
config/service/module *primitives*; this module is just reviewed command
templates. The apply step runs under ``sudo -n``; the dry-run reads current state
(so a missing target or key aborts the apply instead of guessing).
"""

from __future__ import annotations

from ._template import CommandTemplate

TEMPLATES: dict[str, CommandTemplate] = {
    # CVE-2021-4034 (PwnKit): strip / restore the setuid bit on pkexec.
    "harden.disable_pkexec_suid": CommandTemplate(
        "harden.disable_pkexec_suid",
        ["sudo", "-n", "chmod", "0755", "/usr/bin/pkexec"],
        read_only=False,
        dry_run_variant=["stat", "-c", "%a %n", "/usr/bin/pkexec"],
    ),
    "harden.restore_pkexec_suid": CommandTemplate(
        "harden.restore_pkexec_suid",
        ["sudo", "-n", "chmod", "4755", "/usr/bin/pkexec"],
        read_only=False,
        dry_run_variant=["stat", "-c", "%a %n", "/usr/bin/pkexec"],
    ),
    # Sysctl toggles (runtime; persist via /etc/sysctl.d). The dry-run reads the
    # key, so a kernel that lacks it aborts the apply instead of guessing.
    # SACK Panic (CVE-2019-11477/11478/11479): disable / restore TCP SACK.
    "harden.disable_tcp_sack": CommandTemplate(
        "harden.disable_tcp_sack",
        ["sudo", "-n", "sysctl", "-w", "net.ipv4.tcp_sack=0"],
        read_only=False, dry_run_variant=["sysctl", "net.ipv4.tcp_sack"],
    ),
    "harden.enable_tcp_sack": CommandTemplate(
        "harden.enable_tcp_sack",
        ["sudo", "-n", "sysctl", "-w", "net.ipv4.tcp_sack=1"],
        read_only=False, dry_run_variant=["sysctl", "net.ipv4.tcp_sack"],
    ),
    # Multipath TCP attack-surface reduction: disable / restore MPTCP.
    "harden.disable_mptcp": CommandTemplate(
        "harden.disable_mptcp",
        ["sudo", "-n", "sysctl", "-w", "net.mptcp.enabled=0"],
        read_only=False, dry_run_variant=["sysctl", "net.mptcp.enabled"],
    ),
    "harden.enable_mptcp": CommandTemplate(
        "harden.enable_mptcp",
        ["sudo", "-n", "sysctl", "-w", "net.mptcp.enabled=1"],
        read_only=False, dry_run_variant=["sysctl", "net.mptcp.enabled"],
    ),
}
