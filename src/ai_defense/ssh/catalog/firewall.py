"""Allowlisted firewall-rule actions (reviewed, default-deny).

Hardening often means *editing firewall rules* — close a port, restrict a source,
add a CVE-mitigation rule — done through the firewall's own tooling (``ufw`` here),
never raw packet-filter edits, and distinct from *disabling* the firewall (which
the PROTECTED_SERVICES guard forbids). Two safeguards specific to firewall/network
changes (CLAUDE.md 6a), enforced by the executor:

- **Lockout guard** — a rule that would cut the harness's own management SSH is
  refused outright (``FirewallChange.locks_out_management``).
- **Timed auto-revert** — the rule is applied with a scheduled ``systemd-run``
  rollback; a post-apply health check must confirm management is still reachable
  within the window or the change rolls back on its own.

A mitigation file may reference one of these by name but can't define a new one.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FirewallRule:
    name: str
    action: str                      # allow | deny | restrict_source | remove_rule
    port: int
    proto: str = "tcp"
    sources: tuple[str, ...] = ()     # CIDRs for allow-from / restrict_source
    removes: str = "deny"            # for remove_rule: which verb's rule to delete
    revert_after_seconds: int = 120


def _deny_pair(label: str, port: int, proto: str) -> dict:
    """apply = deny the port; reverse = delete that deny rule."""
    return {
        f"firewall.deny_{label}": FirewallRule(
            f"firewall.deny_{label}", "deny", port, proto),
        f"firewall.deny_{label}.reverse": FirewallRule(
            f"firewall.deny_{label}.reverse", "remove_rule", port, proto, removes="deny"),
    }


# Reviewed firewall actions.
FIREWALL_ACTIONS: dict[str, FirewallRule] = {
    # CVE-2018-1000115: memcached UDP (11211) reflection/amplification — block it
    # at the network edge where the service must stay reachable internally.
    **_deny_pair("udp_memcached", 11211, "udp"),
}


# Guard: a reviewed action must name a known ufw verb.
_VERBS = {"allow", "deny", "restrict_source", "remove_rule"}
for _a in FIREWALL_ACTIONS.values():
    if _a.action not in _VERBS:
        raise ValueError(f"firewall action {_a.name!r} has an unknown verb: {_a.action}")
