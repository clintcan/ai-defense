"""Catalog base: the parameterized command template and its safe argv binding.

Commands are built by binding validated params into a fixed argv template, never
by string concatenation of planner-supplied text. Category modules in this
package (``packages``, ``hardening``, …) each expose a ``TEMPLATES`` dict; the
package ``__init__`` merges them into the single allowlist ``CATALOG``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Values bound into argv are constrained to a conservative charset. argv
# execution already avoids shell interpretation, but this rejects obviously
# malformed/hostile values (spaces, shell metacharacters, newlines) defensively.
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:+~=/@-]+$")


def render_argv(tokens: list[str], params: dict[str, Any]) -> list[str]:
    """Bind ``{name}`` tokens from ``params`` into a concrete argv.

    A token is either a literal or exactly ``{name}``. Every placeholder must be
    supplied and every supplied value must match the safe charset.
    """
    out: list[str] = []
    missing: list[str] = []
    for tok in tokens:
        if len(tok) >= 2 and tok[0] == "{" and tok[-1] == "}":
            key = tok[1:-1]
            if key not in params:
                missing.append(key)
                continue
            val = str(params[key])
            if not _SAFE_VALUE.match(val):
                raise ValueError(f"unsafe value for parameter {key!r}: {val!r}")
            out.append(val)
        else:
            out.append(tok)
    if missing:
        raise KeyError(f"missing template parameters: {missing}")
    return out


@dataclass(frozen=True)
class CommandTemplate:
    name: str
    template: list[str]       # argv form, with {placeholders}
    read_only: bool
    dry_run_variant: list[str] | None = None   # e.g. apt-get --simulate

    def render(self, params: dict[str, Any]) -> list[str]:
        return render_argv(self.template, params)

    def render_dry_run(self, params: dict[str, Any]) -> list[str] | None:
        if self.dry_run_variant is None:
            return None
        return render_argv(self.dry_run_variant, params)
