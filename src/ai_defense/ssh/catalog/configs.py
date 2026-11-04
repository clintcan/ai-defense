"""Managed config drop-in operations (reviewed, allowlisted) — write a fixed
file into a conf.d-style directory, or remove it.

The drop-in model is additive and idempotent: applying *writes* the file, so the
reverse is simply *deleting* it — no backup or diff needed (that's the in-place
``ConfigEdit`` primitive's job). A drop-in's target path is fixed here in
reviewed code and must sit directly under an allowlisted directory
(``ALLOWED_DROPIN_DIRS``) — default deny, checked at import and again at execute.

Like command templates, these are referenced by a *mitigation* by name; a
mitigation file can point at one but can't define a new one.
"""

from __future__ import annotations

from dataclasses import dataclass

# Only these conf.d-style directories may receive a managed drop-in. Each holds
# additive, independently-removable files — never a monolithic system file.
ALLOWED_DROPIN_DIRS: tuple[str, ...] = (
    "/etc/sysctl.d/",
    "/etc/modprobe.d/",
    "/etc/ssh/sshd_config.d/",
    "/etc/security/limits.d/",
)


def dir_allowed(path: str) -> bool:
    """True iff ``path`` is a plain filename directly under an allowlisted dir
    (no nesting, no traversal)."""
    for d in ALLOWED_DROPIN_DIRS:
        if path.startswith(d):
            rest = path[len(d):]
            return bool(rest) and "/" not in rest and ".." not in rest
    return False


@dataclass(frozen=True)
class DropInWrite:
    name: str
    path: str                        # fixed; must be under an ALLOWED_DROPIN_DIR
    content: str
    reload: tuple[str, ...] = ()      # argv run after the write (also validates); () = none


@dataclass(frozen=True)
class DropInRemove:
    name: str
    path: str                        # matches a DropInWrite's path
    reload: tuple[str, ...] = ()


_MPTCP_PATH = "/etc/sysctl.d/80-ai-defense-mptcp.conf"

# Allowlisted config actions, keyed by name. A mitigation's template /
# rollback_template may reference one of these (apply / reverse).
CONFIG_ACTIONS: dict[str, DropInWrite | DropInRemove] = {
    # Persist "disable Multipath TCP" across reboot (and apply now via sysctl -p).
    "config.sysctl_mptcp_off": DropInWrite(
        name="config.sysctl_mptcp_off",
        path=_MPTCP_PATH,
        content="# AI Defense: disable Multipath TCP (attack-surface reduction)\n"
                "net.mptcp.enabled = 0\n",
        reload=("sudo", "-n", "sysctl", "-p", _MPTCP_PATH),   # applies + validates
    ),
    "config.sysctl_mptcp_off.remove": DropInRemove(
        name="config.sysctl_mptcp_off.remove",
        path=_MPTCP_PATH,
        reload=("sudo", "-n", "sysctl", "--system"),
    ),
}

# Fail fast if a reviewed action ever points outside the allowlisted dirs.
for _a in CONFIG_ACTIONS.values():
    if not dir_allowed(_a.path):
        raise ValueError(f"config action {_a.name!r} targets a non-allowlisted path: {_a.path}")
