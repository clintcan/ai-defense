"""Known, cited CVE mitigations — published workarounds to apply when the vendor
patch can't be (an EOL OS without ESM, or a fix not yet shipped).

A mitigation is **data, not a command**: an entry names which *allowlisted*
catalog command (``ssh/catalog/``) applies the workaround and which reverses
it, plus the CVE(s) it covers and the advisory it cites (hard rule #6). The
engine never invents a mitigation; it only offers one listed here.

Entries come from two places, merged by ``mitigation_id`` (a file overrides a
built-in of the same id):
  * the built-in defaults below, and
  * an operator **mitigations folder** of ``.yaml`` / ``.yml`` / ``.json`` files
    (one or many mitigations per file), loaded by ``load_mitigations``.

Crucially, the loader is **default-deny on commands**: it rejects any entry whose
``template``/``rollback_template`` is not already in the reviewed catalog
allowlist. So dropping a file can add a CVE→(existing command) mapping and its
citation, but can never introduce a new arbitrary command (hard rules #3/#5) —
a genuinely new command still requires a reviewed catalog entry.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Mitigation:
    mitigation_id: str
    cves: tuple[str, ...]
    title: str
    source_ref: str                 # advisory URL a human can verify (rule #6)
    template: str                   # allowlisted catalog command that applies it
    rollback_template: str          # allowlisted catalog command that reverses it
    description: str = ""
    temporary: bool = True          # a mitigation is a stopgap until the real patch


@dataclass(frozen=True)
class MitigationRegistry:
    """Loaded mitigations, indexed by CVE (what the engine looks up) and by
    mitigation_id (what the toolset maps to a command)."""

    by_id: dict[str, Mitigation] = field(default_factory=dict)
    by_cve: dict[str, Mitigation] = field(default_factory=dict)

    def for_cve(self, cve_id: str) -> Mitigation | None:
        return self.by_cve.get(cve_id)

    def command_for(self, mitigation_id: str) -> Mitigation | None:
        return self.by_id.get(mitigation_id)

    def __len__(self) -> int:
        return len(self.by_id)


# Built-in defaults so the common mitigations work with no folder configured.
_BUILTIN: tuple[Mitigation, ...] = (
    Mitigation(
        mitigation_id="pwnkit-pkexec-suid",
        cves=("CVE-2021-4034",),
        title="Remove the setuid bit from /usr/bin/pkexec (PwnKit workaround)",
        source_ref="https://ubuntu.com/security/CVE-2021-4034",
        template="harden.disable_pkexec_suid",
        rollback_template="harden.restore_pkexec_suid",
        description="remove setuid from /usr/bin/pkexec (reverse: restore 4755)",
    ),
)

_REQUIRED = ("mitigation_id", "cves", "title", "source_ref", "template",
             "rollback_template")


class MitigationError(ValueError):
    """A mitigation entry is malformed or references a non-allowlisted command."""


def mitigation_for(cve_id: str) -> Mitigation | None:
    """Built-in-only lookup (no folder). Convenience for callers that don't load
    a registry."""
    for m in _BUILTIN:
        if cve_id in m.cves:
            return m
    return None


def _coerce(raw: dict) -> Mitigation:
    """Normalize a raw dict (tolerant of a few field aliases) into a Mitigation,
    raising MitigationError if a required field is missing."""
    cves = raw.get("cves") or raw.get("cve")
    if isinstance(cves, str):
        cves = [cves]
    data = {
        "mitigation_id": raw.get("mitigation_id") or raw.get("id"),
        "cves": tuple(cves) if cves else (),
        "title": raw.get("title"),
        "source_ref": raw.get("source_ref") or raw.get("source"),
        "template": raw.get("template"),
        "rollback_template": raw.get("rollback_template") or raw.get("rollback"),
        "description": raw.get("description", ""),
        "temporary": bool(raw.get("temporary", True)),
    }
    missing = [k for k in _REQUIRED if not data.get(k)]
    if missing:
        raise MitigationError(f"missing required field(s): {', '.join(missing)}")
    return Mitigation(**data)


def _entries_from_obj(obj) -> list[dict]:
    """A file may hold one mitigation (dict), a list of them, or {'mitigations': [...]}"""
    if isinstance(obj, dict) and "mitigations" in obj:
        obj = obj["mitigations"]
    if isinstance(obj, dict):
        return [obj]
    if isinstance(obj, list):
        return [o for o in obj if isinstance(o, dict)]
    raise MitigationError("file must be a mitigation object, a list, or {mitigations: [...]}")


def _load_file(path: str) -> list[dict]:
    text = open(path, encoding="utf-8").read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as exc:  # pyyaml is optional
            raise MitigationError("install pyyaml for .yaml files, or use .json") from exc
        try:
            obj = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise MitigationError(f"invalid YAML: {exc}") from exc
        return _entries_from_obj(obj)
    return _entries_from_obj(json.loads(text))


def _default_warn(msg: str) -> None:
    print(f"[mitigations] {msg}", file=sys.stderr)


def load_mitigations(
    folder: str | None = None, *, allowed_templates: Iterable[str],
    builtin: tuple[Mitigation, ...] = _BUILTIN,
    warn: Callable[[str], None] = _default_warn,
) -> MitigationRegistry:
    """Build the mitigation registry from the built-ins plus every mitigation file
    in ``folder``. Invalid entries are **skipped with a warning** (fail-safe — one
    bad file never crashes the engine, and a bad entry is never silently used):

      * a missing required field, or an unparseable file;
      * a ``template``/``rollback_template`` not in ``allowed_templates`` (the
        reviewed catalog) — default deny, so a file can't add a new command.

    Later entries override earlier ones by ``mitigation_id`` (folder overrides a
    built-in), so an operator can retune a built-in's citation or command mapping
    without editing code.
    """
    allowed = set(allowed_templates)
    collected: list[Mitigation] = list(builtin)

    if folder and os.path.isdir(folder):
        for name in sorted(os.listdir(folder)):
            if not name.endswith((".yaml", ".yml", ".json")):
                continue
            path = os.path.join(folder, name)
            try:
                raws = _load_file(path)
            except (OSError, ValueError, MitigationError) as exc:
                warn(f"skipped {name}: {exc}")
                continue
            for raw in raws:
                try:
                    collected.append(_coerce(raw))
                except MitigationError as exc:
                    warn(f"skipped an entry in {name}: {exc}")

    by_id: dict[str, Mitigation] = {}
    by_cve: dict[str, Mitigation] = {}
    for m in collected:
        if m.template not in allowed or m.rollback_template not in allowed:
            bad = m.template if m.template not in allowed else m.rollback_template
            warn(f"skipped '{m.mitigation_id}': command '{bad}' is not allowlisted "
                 "in the catalog (add it there, reviewed, first)")
            continue
        by_id[m.mitigation_id] = m
        for cve in m.cves:
            by_cve[cve] = m          # last wins -> folder overrides built-in
    return MitigationRegistry(by_id=by_id, by_cve=by_cve)
