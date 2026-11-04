"""Allowlisted, parameterized command templates — the ONLY commands reachable.

Default deny (CLAUDE.md #3/#5): a command is unreachable until it exists as a
reviewed template here. To keep the allowlist from becoming one giant file as
mitigations grow, it is split into small, reviewed **category modules**
(``packages``, ``hardening``, …) each exposing a ``TEMPLATES`` dict; this
``__init__`` merges them into one ``CATALOG``. Adding a command is therefore
still a reviewed **code** change, never a drop-in data file — that distinction
is the whole point of the allowlist (a mitigation *file* may only reference a
template that already lives here).

Public API is unchanged: ``CATALOG``, ``CommandTemplate``, ``render_argv``.
"""

from __future__ import annotations

from ..hardening import PrimitiveKind
from . import hardening, osupgrade, packages
from ._template import CommandTemplate, render_argv
from .configs import (
    ALLOWED_DROPIN_DIRS,
    ALLOWED_EDIT_PATHS,
    CONFIG_ACTIONS,
    ConfigBlockRemove,
    ConfigBlockWrite,
    DropInRemove,
    DropInWrite,
    dir_allowed,
    edit_path_allowed,
)
from .firewall import FIREWALL_ACTIONS, FirewallRule
from .modules import MODULE_ACTIONS, ModuleBlacklist, ModuleUnblacklist
from .services import SERVICE_ACTIONS, ServiceStateChange


def _merge(*categories: dict[str, CommandTemplate]) -> dict[str, CommandTemplate]:
    """Merge category template dicts, refusing a name defined in two categories
    (default-deny hygiene: a collision is a bug, not a silent override)."""
    catalog: dict[str, CommandTemplate] = {}
    for category in categories:
        for name, template in category.items():
            if name in catalog:
                raise ValueError(f"duplicate catalog template name across categories: {name!r}")
            catalog[name] = template
    return catalog


CATALOG: dict[str, CommandTemplate] = _merge(
    packages.TEMPLATES, hardening.TEMPLATES, osupgrade.TEMPLATES)


def _merge_actions(*dicts: dict) -> dict:
    """Merge category action dicts, refusing a name defined twice."""
    merged: dict = {}
    for d in dicts:
        for name, action in d.items():
            if name in merged:
                raise ValueError(f"duplicate catalog action name across categories: {name!r}")
            merged[name] = action
    return merged


# Every reviewed managed-primitive action (config edits + kernel modules +
# services + …), keyed by name. A mitigation references one of these; the
# ConfigExecutor dispatches it by type. CONFIG_ACTIONS stays the config-only view
# for back-compat.
PRIMITIVE_ACTIONS: dict = _merge_actions(
    CONFIG_ACTIONS, MODULE_ACTIONS, SERVICE_ACTIONS, FIREWALL_ACTIONS)


def action_primitive_kind(action) -> PrimitiveKind:
    """The PrimitiveKind a reviewed action belongs to (for audit/rollback/listing)."""
    if isinstance(action, (ModuleBlacklist, ModuleUnblacklist)):
        return PrimitiveKind.KERNEL_MODULE
    if isinstance(action, ServiceStateChange):
        return PrimitiveKind.SERVICE
    if isinstance(action, FirewallRule):
        return PrimitiveKind.FIREWALL_RULE
    return PrimitiveKind.CONFIG_EDIT    # DropIn*/ConfigBlock*


__all__ = ["CATALOG", "CommandTemplate", "render_argv",
           "CONFIG_ACTIONS", "PRIMITIVE_ACTIONS", "action_primitive_kind",
           "DropInWrite", "DropInRemove", "dir_allowed",
           "ALLOWED_DROPIN_DIRS", "ConfigBlockWrite", "ConfigBlockRemove",
           "edit_path_allowed", "ALLOWED_EDIT_PATHS",
           "MODULE_ACTIONS", "ModuleBlacklist", "ModuleUnblacklist",
           "SERVICE_ACTIONS", "ServiceStateChange",
           "FIREWALL_ACTIONS", "FirewallRule"]
