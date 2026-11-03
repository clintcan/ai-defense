"""Allowlisted, parameterized command templates (prevents injection).

Commands are built by binding validated params into a fixed template, never by
string concatenation of planner-supplied text. A template unknown to the
catalog cannot be executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CommandTemplate:
    name: str
    template: list[str]       # argv form, with {placeholders}
    read_only: bool
    dry_run_variant: list[str] | None = None   # e.g. apt-get --simulate

    def render(self, params: dict[str, Any]) -> list[str]:
        """Bind validated params into argv. TODO: strict per-param validation."""
        raise NotImplementedError


CATALOG: dict[str, CommandTemplate] = {
    # Examples (read-only subset is what the authenticated scanner may use):
    # "apt.list_upgradable": CommandTemplate("apt.list_upgradable",
    #     ["apt", "list", "--upgradable"], read_only=True),
    # "apt.install_security": CommandTemplate("apt.install_security",
    #     ["apt-get", "install", "--only-upgrade", "-y", "{package}"],
    #     read_only=False, dry_run_variant=["apt-get", "install", "--simulate", "{package}"]),
}
