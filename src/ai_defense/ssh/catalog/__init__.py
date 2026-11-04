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

from . import hardening, packages
from ._template import CommandTemplate, render_argv


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


CATALOG: dict[str, CommandTemplate] = _merge(packages.TEMPLATES, hardening.TEMPLATES)

__all__ = ["CATALOG", "CommandTemplate", "render_argv"]
