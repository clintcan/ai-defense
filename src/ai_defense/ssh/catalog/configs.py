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
    "/etc/nginx/conf.d/",       # included inside nginx's http{} block
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
    validate: tuple[str, ...] = ()    # argv run after the write (rollback on failure); () = none
    reload: tuple[str, ...] = ()      # argv run after validation passes; () = none


@dataclass(frozen=True)
class DropInRemove:
    name: str
    path: str                        # matches a DropInWrite's path
    reload: tuple[str, ...] = ()


# In-place edits (for files with no conf.d) touch only a marker-delimited block
# the tool owns, and only in these reviewed, allowlisted files — default deny.
ALLOWED_EDIT_PATHS: tuple[str, ...] = (
    "/etc/ssh/sshd_config",
    "/etc/sysctl.conf",
    "/etc/login.defs",
)


def edit_path_allowed(path: str) -> bool:
    return path in ALLOWED_EDIT_PATHS


@dataclass(frozen=True)
class ConfigBlockWrite:
    name: str
    path: str                        # existing file; must be in ALLOWED_EDIT_PATHS
    marker: str                      # unique id of the managed block
    body: str                        # managed block content
    validate: tuple[str, ...] = ()
    reload: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConfigBlockRemove:
    name: str
    path: str
    marker: str
    validate: tuple[str, ...] = ()
    reload: tuple[str, ...] = ()


_MPTCP_PATH = "/etc/sysctl.d/80-ai-defense-mptcp.conf"
_SSHD = "/etc/ssh/sshd_config"
_NGINX_HTTP2_PATH = "/etc/nginx/conf.d/99-ai-defense-http2.conf"

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
    # In-place (no conf.d on older OpenSSH): disable X11 forwarding in a managed
    # block. Benign — it can't sever SSH access. Validated by `sshd -t`.
    "config.sshd_disable_x11": ConfigBlockWrite(
        name="config.sshd_disable_x11", path=_SSHD, marker="sshd-x11",
        body="X11Forwarding no",
        validate=("sudo", "-n", "sshd", "-t"),
        reload=("sudo", "-n", "systemctl", "reload", "sshd"),
    ),
    "config.sshd_disable_x11.remove": ConfigBlockRemove(
        name="config.sshd_disable_x11.remove", path=_SSHD, marker="sshd-x11",
        validate=("sudo", "-n", "sshd", "-t"),
        reload=("sudo", "-n", "systemctl", "reload", "sshd"),
    ),
    # HTTP/2 Rapid Reset (CVE-2023-44487): cap concurrent streams per connection
    # so a reset-flood can't amplify. A conf.d drop-in is included in nginx's
    # http{} block. Validated by `nginx -t` (which rejects the directive on nginx
    # builds that dropped it, so a mismatch rolls back cleanly rather than lingering).
    "config.nginx_http2_rapidreset": DropInWrite(
        name="config.nginx_http2_rapidreset",
        path=_NGINX_HTTP2_PATH,
        content="# AI Defense: HTTP/2 Rapid Reset mitigation (CVE-2023-44487)\n"
                "# Bound concurrent streams; the vendor patch is the real fix.\n"
                "http2_max_concurrent_streams 128;\n",
        validate=("sudo", "-n", "nginx", "-t"),
        reload=("sudo", "-n", "systemctl", "reload", "nginx"),
    ),
    "config.nginx_http2_rapidreset.remove": DropInRemove(
        name="config.nginx_http2_rapidreset.remove",
        path=_NGINX_HTTP2_PATH,
        reload=("sudo", "-n", "systemctl", "reload", "nginx"),
    ),
}


def _action_path_ok(a) -> bool:
    if isinstance(a, (DropInWrite, DropInRemove)):
        return dir_allowed(a.path)
    if isinstance(a, (ConfigBlockWrite, ConfigBlockRemove)):
        return edit_path_allowed(a.path)
    return False


# Fail fast if a reviewed action ever points at a non-allowlisted path.
for _a in CONFIG_ACTIONS.values():
    if not _action_path_ok(_a):
        raise ValueError(f"config action {_a.name!r} targets a non-allowlisted path: {_a.path}")
