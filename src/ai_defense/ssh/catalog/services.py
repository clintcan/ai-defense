"""Allowlisted service-state actions (reviewed, default-deny).

Disabling an unneeded or vulnerable service is a managed primitive: a
``systemctl disable --now`` (or ``mask``) with the unit checked **denylist-first**
against ``PROTECTED_SERVICES`` — security-critical units (auditd, firewalld, ufw,
sshd, …) can never be disabled/masked, even with approval (CLAUDE.md 6a). The
reverse re-enables (or unmasks) the unit.

Disabling a *protective* service is refused at import **and** at execute time;
disabling a *vulnerable/unneeded* one is allowed. A mitigation file may reference
one of these by name but can't define a new one.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..hardening import ServiceAction, ServiceChange


@dataclass(frozen=True)
class ServiceStateChange:
    name: str
    unit: str
    action: ServiceAction

    def is_blocked(self) -> bool:
        """Delegates to the reviewed ServiceChange guard (protective units)."""
        return ServiceChange(self.unit, self.action).is_blocked()


def _disable_pair(unit: str) -> dict:
    """apply = disable --now; reverse = enable --now."""
    return {
        f"service.disable_{unit}": ServiceStateChange(
            f"service.disable_{unit}", unit, ServiceAction.DISABLE),
        f"service.disable_{unit}.reverse": ServiceStateChange(
            f"service.disable_{unit}.reverse", unit, ServiceAction.ENABLE),
    }


# Reviewed service actions. Each disables an unneeded/legacy-exposure unit;
# none is a protected unit (enforced below).
SERVICE_ACTIONS: dict[str, ServiceStateChange] = {
    **_disable_pair("rpcbind"),         # RPC portmapper — legacy, broad surface
    **_disable_pair("avahi-daemon"),    # mDNS/zeroconf — rarely needed on servers
    **_disable_pair("cups"),            # print service — not needed on servers
}


# Fail fast if a reviewed action would ever disable/mask a protected unit.
for _a in SERVICE_ACTIONS.values():
    if _a.is_blocked():
        raise ValueError(f"service action {_a.name!r} targets a protected unit: {_a.unit}")
