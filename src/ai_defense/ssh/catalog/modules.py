"""Allowlisted kernel-module hardening actions (reviewed, default-deny).

Blacklisting an unused/insecure kernel module is a managed primitive: write a
``/etc/modprobe.d`` drop-in (``blacklist`` + ``install … /bin/true`` so it can't
be auto-loaded) and unload it at runtime with ``modprobe -r``. The reverse removes
the drop-in so the module may load again.

The module name is checked against ``HARDENING_MODULE_ALLOWLIST`` (the reviewed set
of hardening targets) at import **and** at execute time — the planner can never
blacklist an arbitrary module, only a reviewed one. Like every catalog action, a
mitigation *file* may reference one of these by name but can't define a new one.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..hardening import HARDENING_MODULE_ALLOWLIST

MODPROBE_DIR = "/etc/modprobe.d/"


def _dropin_path(module: str) -> str:
    return f"{MODPROBE_DIR}ai-defense-blacklist-{module}.conf"


@dataclass(frozen=True)
class ModuleBlacklist:
    name: str
    module: str                      # must be in HARDENING_MODULE_ALLOWLIST

    @property
    def path(self) -> str:
        return _dropin_path(self.module)


@dataclass(frozen=True)
class ModuleUnblacklist:
    name: str
    module: str

    @property
    def path(self) -> str:
        return _dropin_path(self.module)


def _blacklist_pair(module: str) -> dict:
    return {
        f"module.blacklist_{module}": ModuleBlacklist(f"module.blacklist_{module}", module),
        f"module.unblacklist_{module}": ModuleUnblacklist(f"module.unblacklist_{module}", module),
    }


# Reviewed kernel-module actions. Each target is an attack-surface-reduction
# module from the allowlist; apply = blacklist drop-in + runtime unload, reverse =
# remove the drop-in.
MODULE_ACTIONS: dict[str, ModuleBlacklist | ModuleUnblacklist] = {
    **_blacklist_pair("dccp"),        # uncommon transport (CVE-2017-6074 class)
    **_blacklist_pair("sctp"),        # uncommon transport, broad attack surface
    **_blacklist_pair("usb-storage"), # removable media / data-exfil surface
    **_blacklist_pair("firewire-core"),  # DMA attack surface
}


# Fail fast if a reviewed action ever targets a module not on the hardening
# allowlist (default deny — mirrors configs.py's import-time path check).
for _a in MODULE_ACTIONS.values():
    if _a.module not in HARDENING_MODULE_ALLOWLIST:
        raise ValueError(f"module action {_a.name!r} targets a non-allowlisted module: {_a.module}")
