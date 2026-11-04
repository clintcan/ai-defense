"""Package-manager command templates: query (read-only) and security upgrade.

The apply step runs under ``sudo -n`` (cloud images log in as a non-root user
with passwordless sudo; ``-n`` fails fast rather than hanging on a prompt). The
dry-run stays unprivileged — it only simulates.
"""

from __future__ import annotations

from ._template import CommandTemplate

TEMPLATES: dict[str, CommandTemplate] = {
    # --- read-only (scanner subset) ------------------------------------
    "apt.list_upgradable": CommandTemplate(
        "apt.list_upgradable", ["apt", "list", "--upgradable"], read_only=True,
    ),
    "dnf.updateinfo": CommandTemplate(
        "dnf.updateinfo", ["dnf", "updateinfo", "list", "security"], read_only=True,
    ),
    # --- mutating (approval-gated), each with a dry-run variant ---------
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
}
