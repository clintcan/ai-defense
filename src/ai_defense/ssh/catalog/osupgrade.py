"""OS release-upgrade command templates (reviewed, allowlisted).

These drive an **in-place** release upgrade and the reboot that follows, plus a
read-only probe used to confirm the new release after the host comes back. They
are the mutating core of the strongly-gated ``OS_UPGRADE`` workflow (CLAUDE.md 6c)
— reachable only through that workflow, under the ``os_upgrade_canary`` /
``os_upgrade_fleet`` action classes, after a mandatory snapshot and human
approval.

Ubuntu drives the whole upgrade through ``do-release-upgrade``. Debian has no
equivalent single wrapper: the sequence is rewrite ``/etc/apt/sources.list``
(the old codename -> the new one — ``AptSourcesCodenameSwap`` in
``catalog/configs.py``, run through the managed backup/diff/validate/restore
edit primitive, validated by ``apt-get update``), then ``apt.full_upgrade``
below, then the same ``os.reboot``.
"""

from __future__ import annotations

from ._template import CommandTemplate

TEMPLATES: dict[str, CommandTemplate] = {
    # Read-only: confirm the running release (used as the post-reboot reconnect
    # probe and the health check — parse VERSION_ID from the output).
    "os.read_release": CommandTemplate(
        "os.read_release", ["cat", "/etc/os-release"], read_only=True,
    ),
    # Mutating: drive the in-place release upgrade non-interactively. The dry-run
    # (`do-release-upgrade -c`) only *checks* whether a new release is available
    # and changes nothing, so a host with no upgrade available aborts cleanly.
    "os.do_release_upgrade": CommandTemplate(
        "os.do_release_upgrade",
        ["sudo", "-n", "do-release-upgrade", "-f", "DistUpgradeViewNonInteractive"],
        read_only=False,
        dry_run_variant=["do-release-upgrade", "-c"],
    ),
    # Mutating: reboot into the upgraded system. No dry-run (a reboot can't be
    # simulated); the workflow runs it without a dry-run and then polls for the
    # host to come back via os.read_release.
    "os.reboot": CommandTemplate(
        "os.reboot", ["sudo", "-n", "systemctl", "reboot"], read_only=False,
    ),
    # Debian: the actual release-level upgrade, run after sources.list is
    # repointed at the new codename and `apt-get update` has validated it.
    # `--simulate` is apt's dry-run (no download, no change) — the direct
    # equivalent of Ubuntu's `do-release-upgrade -c`.
    "apt.full_upgrade": CommandTemplate(
        "apt.full_upgrade",
        ["sudo", "-n", "apt-get", "-y", "full-upgrade"],
        read_only=False,
        dry_run_variant=["apt-get", "full-upgrade", "--simulate"],
    ),
}
