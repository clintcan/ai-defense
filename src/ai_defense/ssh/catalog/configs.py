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

import re
from dataclasses import dataclass

# Real Debian/Ubuntu codenames are plain lowercase words (buster, bullseye, …).
# Defense in depth: reject anything else even though the only legitimate caller
# (the OS_UPGRADE workflow) sources these from the reviewed release table, never
# planner text.
_CODENAME_RE = re.compile(r"^[a-z0-9]+$")

# Only these conf.d-style directories may receive a managed drop-in. Each holds
# additive, independently-removable files — never a monolithic system file.
ALLOWED_DROPIN_DIRS: tuple[str, ...] = (
    "/etc/sysctl.d/",
    "/etc/modprobe.d/",
    "/etc/ssh/sshd_config.d/",
    "/etc/security/limits.d/",
    "/etc/nginx/conf.d/",       # included inside nginx's http{} block
    "/etc/php/8.1/fpm/conf.d/", # Ubuntu-packaged PHP-FPM (22.04's default 8.1)
    "/opt/bitnami/php/etc/conf.d/",  # Bitnami LAMP's bundled PHP (not the distro package)
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
    "/etc/apt/sources.list",   # Debian in-place release upgrade: codename swap
)


def edit_path_allowed(path: str) -> bool:
    return path in ALLOWED_EDIT_PATHS


# Every in-place edit keeps the pre-edit file here (overwritten by each new edit,
# so it always holds the state before the most recent one).
BACKUP_SUFFIX = ".ai-defense.bak"
# Where a restore keeps the content it replaced, so the restore is itself undoable.
PRE_RESTORE_SUFFIX = ".ai-defense.pre-restore"

# (validate, reload) run after restoring an allowlisted file from its backup; a
# path absent here is restored unvalidated. sources.list has none on purpose:
# `apt-get update` needs live repos, which a retired release's file won't have.
RESTORE_CHECKS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "/etc/ssh/sshd_config": (("sudo", "-n", "sshd", "-t"),
                             ("sudo", "-n", "systemctl", "reload", "sshd")),
}


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


@dataclass(frozen=True)
class AptSourcesCodenameSwap:
    """Debian in-place upgrade step: rewrite every whole-word occurrence of
    ``old_codename`` to ``new_codename`` in an apt sources file (fixed path, must
    be in ``ALLOWED_EDIT_PATHS``). Unlike the other in-place edits this one is
    parameterized per-call (the codenames vary per host/upgrade) rather than a
    fixed catalog singleton — the executor still enforces the path allowlist on
    every call regardless of where the instance came from, so a dynamically built
    one is checked exactly like a static entry. ``old_codename``/``new_codename``
    must come from the reviewed release table (``upgrade/releases.py``), never
    from planner-supplied text."""
    name: str
    path: str
    old_codename: str
    new_codename: str
    validate: tuple[str, ...] = ()
    reload: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for cn in (self.old_codename, self.new_codename):
            if not _CODENAME_RE.match(cn):
                raise ValueError(f"unsafe codename value: {cn!r}")


_MPTCP_PATH = "/etc/sysctl.d/80-ai-defense-mptcp.conf"
_SSHD = "/etc/ssh/sshd_config"
_NGINX_HTTP2_PATH = "/etc/nginx/conf.d/99-ai-defense-http2.conf"
_PHP_FPM_HARDEN_PATH = "/etc/php/8.1/fpm/conf.d/99-ai-defense-hardening.ini"
_PHP_BITNAMI_HARDEN_PATH = "/opt/bitnami/php/etc/conf.d/99-ai-defense-hardening.ini"

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
    # PHP "session upload progress" is abusable in LFI->RCE (an attacker seeds
    # attacker-controlled bytes into a predictable session file, then includes it).
    # Turning it off is a safe hardening — it changes no application behaviour,
    # unlike disable_functions. PHP_INI_PERDIR, so it lives in a conf.d .ini.
    # Ubuntu-packaged PHP-FPM only (path/version-specific); on another layout the
    # `tee`/validate fails and nothing is applied.
    "config.php_disable_upload_progress": DropInWrite(
        name="config.php_disable_upload_progress",
        path=_PHP_FPM_HARDEN_PATH,
        content="; AI Defense: close the session-upload-progress LFI->RCE vector\n"
                "session.upload_progress.enabled = Off\n",
        validate=("sudo", "-n", "php-fpm8.1", "-t"),
        reload=("sudo", "-n", "systemctl", "reload", "php8.1-fpm"),
    ),
    "config.php_disable_upload_progress.remove": DropInRemove(
        name="config.php_disable_upload_progress.remove",
        path=_PHP_FPM_HARDEN_PATH,
        reload=("sudo", "-n", "systemctl", "reload", "php8.1-fpm"),
    ),
    # Same hardening for Bitnami LAMP: PHP is bundled under /opt/bitnami, not the
    # distro package, and runs as Apache mod_php (no php-fpm). Apache's mod_php and
    # the bundled `php` CLI share the same conf.d scan dir, so `php -v` is a
    # best-effort smoke check before Apache is restarted via Bitnami's own
    # ctlscript.sh — it catches gross corruption (a broken PHP load), not a strict
    # ini syntax validator the way `nginx -t`/`sshd -t` are. The written content is
    # a single fixed, reviewed directive, so that residual risk is minimal.
    "config.php_disable_upload_progress_bitnami": DropInWrite(
        name="config.php_disable_upload_progress_bitnami",
        path=_PHP_BITNAMI_HARDEN_PATH,
        content="; AI Defense: close the session-upload-progress LFI->RCE vector\n"
                "session.upload_progress.enabled = Off\n",
        validate=("sudo", "-n", "/opt/bitnami/php/bin/php", "-v"),
        reload=("sudo", "-n", "/opt/bitnami/ctlscript.sh", "restart", "apache"),
    ),
    "config.php_disable_upload_progress_bitnami.remove": DropInRemove(
        name="config.php_disable_upload_progress_bitnami.remove",
        path=_PHP_BITNAMI_HARDEN_PATH,
        reload=("sudo", "-n", "/opt/bitnami/ctlscript.sh", "restart", "apache"),
    ),
}


def _action_path_ok(a) -> bool:
    if isinstance(a, (DropInWrite, DropInRemove)):
        return dir_allowed(a.path)
    if isinstance(a, (ConfigBlockWrite, ConfigBlockRemove, AptSourcesCodenameSwap)):
        return edit_path_allowed(a.path)
    return False


# Fail fast if a reviewed action ever points at a non-allowlisted path.
for _a in CONFIG_ACTIONS.values():
    if not _action_path_ok(_a):
        raise ValueError(f"config action {_a.name!r} targets a non-allowlisted path: {_a.path}")
