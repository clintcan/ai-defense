"""Managed configuration primitives for hardening/mitigation remediation.

Remediation is often not a package install but a *configuration change*: editing
config files, blacklisting kernel modules, or disabling/enabling services. These
are expressed as declarative, reviewable operations (never free-form shell
edits) so they can be validated, diffed, and rolled back. See CLAUDE.md
component 6a.

All operations here still flow through the normal pipeline: denylist check ->
dry-run/validate -> human approval -> execute (vault-issued key) -> audit, with
a recorded rollback action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PrimitiveKind(str, Enum):
    CONFIG_EDIT = "config_edit"
    KERNEL_MODULE = "kernel_module"
    SERVICE = "service"


# --- config edits --------------------------------------------------------

class ConfigOp(str, Enum):
    SET_KEY = "set_key"            # key value  (e.g. sshd_config PermitRootLogin no)
    ENSURE_LINE = "ensure_line"    # idempotently ensure a line is present
    ENSURE_BLOCK = "ensure_block"  # managed, marker-delimited block
    REMOVE_LINE = "remove_line"


# Syntax validators run BEFORE apply+reload. No validator -> require stronger
# review. Keyed by a logical config target.
CONFIG_VALIDATORS: dict[str, list[str]] = {
    "sshd_config": ["sshd", "-t"],
    "nginx": ["nginx", "-t"],
    "sudoers": ["visudo", "-c"],
    "sysctl": ["sysctl", "-p", "--dry-run"],
}


@dataclass(frozen=True)
class ConfigEdit:
    target: str                    # logical name -> real path resolved by executor
    op: ConfigOp
    key: str | None = None
    value: str | None = None
    line: str | None = None
    reason: str = ""
    cve_ref: str | None = None
    # executor fills these in: backup path + unified diff shown to approver
    backup_path: str | None = None
    diff: str | None = None


# --- kernel modules ------------------------------------------------------

# Only modules on this hardening allowlist may be blacklisted/disabled by the
# planner. Extend via review.
HARDENING_MODULE_ALLOWLIST: set[str] = {
    "dccp", "sctp", "rds", "tipc",        # uncommon network protocols
    "usb-storage", "firewire-core",       # removable media / DMA
    "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf",  # rare filesystems
}


@dataclass(frozen=True)
class KernelModuleChange:
    module: str
    disable: bool                  # True -> blacklist drop-in + modprobe -r
    reason: str = ""
    cve_ref: str | None = None


# --- services ------------------------------------------------------------

class ServiceAction(str, Enum):
    ENABLE = "enable"
    DISABLE = "disable"
    MASK = "mask"
    START = "start"
    STOP = "stop"


# Security-critical units that may NEVER be disabled/masked, even with approval.
# This is checked in addition to ssh.denylist.
PROTECTED_SERVICES: set[str] = {
    "auditd", "firewalld", "ufw", "nftables", "iptables",
    "sshd", "fail2ban", "apparmor", "selinux",
}


@dataclass(frozen=True)
class ServiceChange:
    unit: str
    action: ServiceAction
    reason: str = ""
    cve_ref: str | None = None

    def is_blocked(self) -> bool:
        """Disabling/masking/stopping a protective service is never allowed."""
        disabling = self.action in (ServiceAction.DISABLE, ServiceAction.MASK, ServiceAction.STOP)
        return disabling and self.unit in PROTECTED_SERVICES


# --- rollback ------------------------------------------------------------

@dataclass(frozen=True)
class RollbackAction:
    """Recorded alongside every applied primitive (CLAUDE.md audit & rollback).

    e.g. restore ``backup_path`` over the config file; re-enable a disabled
    service; remove a modprobe.d blacklist drop-in.
    """

    kind: PrimitiveKind
    description: str
    payload: dict[str, Any] = field(default_factory=dict)
