"""Hardening primitives must respect protected services and the module allowlist."""

from ai_defense.ssh.hardening import (
    HARDENING_MODULE_ALLOWLIST,
    FirewallAction,
    FirewallChange,
    ServiceAction,
    ServiceChange,
)

MGMT_PORT = 22
MGMT_SRC = ("10.0.0.0/24",)


def test_cannot_disable_auditd():
    assert ServiceChange("auditd", ServiceAction.DISABLE).is_blocked()


def test_cannot_mask_firewalld():
    assert ServiceChange("firewalld", ServiceAction.MASK).is_blocked()


def test_can_disable_vulnerable_service():
    # a legitimate hardening target, not protective
    assert not ServiceChange("telnet.socket", ServiceAction.DISABLE).is_blocked()


def test_can_enable_protective_service():
    # enabling a protected service is fine; only disabling is blocked
    assert not ServiceChange("auditd", ServiceAction.ENABLE).is_blocked()


def test_module_allowlist_contains_known_hardening_targets():
    assert {"dccp", "usb-storage"} <= HARDENING_MODULE_ALLOWLIST


def test_firewall_deny_mgmt_port_is_lockout():
    fw = FirewallChange(FirewallAction.DENY, port=22, proto="tcp")
    assert fw.locks_out_management(MGMT_PORT, MGMT_SRC)


def test_firewall_restrict_mgmt_without_our_source_is_lockout():
    fw = FirewallChange(FirewallAction.RESTRICT_SOURCE, port=22, sources=("203.0.113.0/24",))
    assert fw.locks_out_management(MGMT_PORT, MGMT_SRC)


def test_firewall_restrict_mgmt_including_our_source_ok():
    fw = FirewallChange(FirewallAction.RESTRICT_SOURCE, port=22,
                        sources=("10.0.0.0/24", "203.0.113.0/24"))
    assert not fw.locks_out_management(MGMT_PORT, MGMT_SRC)


def test_firewall_harden_other_port_ok():
    # closing a vulnerable service port is legitimate hardening, not a lockout
    fw = FirewallChange(FirewallAction.DENY, port=23, proto="tcp")  # telnet
    assert not fw.locks_out_management(MGMT_PORT, MGMT_SRC)
