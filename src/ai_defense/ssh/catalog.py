"""Allowlisted, parameterized command templates (prevents injection).

Commands are built by binding validated params into a fixed argv template, never
by string concatenation of planner-supplied text. A template unknown to the
catalog cannot be executed.

Package installs/updates live here as templates. Configuration-change
remediations (config file edits, kernel module blacklisting, service
enable/disable) are NOT free-form commands — they go through the managed,
declarative primitives in ``ai_defense.ssh.hardening`` (CLAUDE.md component 6a),
which add backup, diff, syntax validation, the protected-service guard, and a
recorded rollback action.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Values bound into argv are also constrained to a conservative charset. argv
# execution already avoids shell interpretation, but this rejects obviously
# malformed/hostile values (spaces, shell metacharacters, newlines) defensively.
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:+~=/@-]+$")


def render_argv(tokens: list[str], params: dict[str, Any]) -> list[str]:
    """Bind ``{name}`` tokens from ``params`` into a concrete argv.

    A token is either a literal or exactly ``{name}``. Every placeholder must be
    supplied and every supplied value must match the safe charset.
    """
    out: list[str] = []
    missing: list[str] = []
    for tok in tokens:
        if len(tok) >= 2 and tok[0] == "{" and tok[-1] == "}":
            key = tok[1:-1]
            if key not in params:
                missing.append(key)
                continue
            val = str(params[key])
            if not _SAFE_VALUE.match(val):
                raise ValueError(f"unsafe value for parameter {key!r}: {val!r}")
            out.append(val)
        else:
            out.append(tok)
    if missing:
        raise KeyError(f"missing template parameters: {missing}")
    return out


@dataclass(frozen=True)
class CommandTemplate:
    name: str
    template: list[str]       # argv form, with {placeholders}
    read_only: bool
    dry_run_variant: list[str] | None = None   # e.g. apt-get --simulate

    def render(self, params: dict[str, Any]) -> list[str]:
        return render_argv(self.template, params)

    def render_dry_run(self, params: dict[str, Any]) -> list[str] | None:
        if self.dry_run_variant is None:
            return None
        return render_argv(self.dry_run_variant, params)


CATALOG: dict[str, CommandTemplate] = {
    # --- read-only (scanner subset) -------------------------------------
    "apt.list_upgradable": CommandTemplate(
        "apt.list_upgradable", ["apt", "list", "--upgradable"], read_only=True,
    ),
    "dnf.updateinfo": CommandTemplate(
        "dnf.updateinfo", ["dnf", "updateinfo", "list", "security"], read_only=True,
    ),
    # --- mutating (approval-gated), each with a dry-run variant ----------
    # The APPLY step runs under `sudo -n`: cloud images log in as a non-root user
    # (ubuntu/bitnami/ec2-user) with passwordless sudo, so a privileged change
    # needs sudo, and `-n` fails fast (never hangs on a password prompt) where it
    # isn't configured. Dry-runs stay unprivileged — they only read / simulate.
    "apt.install_security": CommandTemplate(
        "apt.install_security",
        ["sudo", "-n", "apt-get", "install", "--only-upgrade", "-y", "{package}"],
        read_only=False,
        dry_run_variant=["apt-get", "install", "--only-upgrade", "--simulate", "{package}"],
    ),
    "dnf.upgrade_security": CommandTemplate(
        "dnf.upgrade_security",
        ["sudo", "-n", "dnf", "upgrade", "-y", "--security", "{package}"],
        read_only=False,
        dry_run_variant=["dnf", "upgrade", "--assumeno", "--security", "{package}"],
    ),
    # --- hardening mitigations (approval-gated), fixed target, reversible ----
    # CVE-2021-4034 (PwnKit): strip / restore the setuid bit on pkexec. Fixed
    # argv on a fixed path (no parameters) -> no injection surface. The dry-run
    # just reads the current mode (unprivileged) so the approver sees state and a
    # missing binary aborts the apply.
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
}
