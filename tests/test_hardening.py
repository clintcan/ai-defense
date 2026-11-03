"""Hardening primitives must respect protected services and the module allowlist."""

from ai_defense.ssh.hardening import (
    HARDENING_MODULE_ALLOWLIST,
    ServiceAction,
    ServiceChange,
)


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
