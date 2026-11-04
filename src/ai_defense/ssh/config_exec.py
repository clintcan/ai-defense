"""Executor for managed config changes over SSH — drop-in files and in-place
marker-block edits.

Every argv goes through ``SSHExecutor.run_one`` (denylist + output cap). A
privileged write uses ``sudo -n tee <path>`` fed the body on stdin (no shell
redirection, no sftp).

- **Drop-ins** (``DropInWrite``/``DropInRemove``): write/remove a whole file in an
  allowlisted conf.d dir; reverse = delete it.
- **In-place edits** (``ConfigBlockWrite``/``ConfigBlockRemove``): read the file,
  insert/replace/remove only a marker-delimited block the tool owns, **back up**
  the file first, show a **diff**, write, **validate** (``sshd -t`` etc.), and
  **restore from backup** if validation fails — the CLAUDE.md 6a dance.

All paths are checked against the allowlists (default deny). Returns an
:class:`ExecOutcome` so the mitigation tool treats every action kind uniformly.
"""

from __future__ import annotations

import difflib

from .catalog import (
    ConfigBlockRemove,
    ConfigBlockWrite,
    DropInRemove,
    DropInWrite,
    dir_allowed,
    edit_path_allowed,
)
from .config_edit import ensure_block, remove_block
from .executor import ExecOutcome, SSHExecutor


class ConfigExecutor:
    def __init__(self, executor: SSHExecutor) -> None:
        self._ex = executor

    def apply(self, action, *, host: str, key: str,
              user: str = "root", port: int = 22) -> ExecOutcome:
        if isinstance(action, DropInWrite):
            return self._write(action, host=host, key=key, user=user, port=port)
        if isinstance(action, DropInRemove):
            return self._remove(action, host=host, key=key, user=user, port=port)
        if isinstance(action, (ConfigBlockWrite, ConfigBlockRemove)):
            return self._edit(action, host=host, key=key, user=user, port=port)
        return ExecOutcome(applied=False, resolved_command="",
                           blocked_reason=f"unknown config action: {type(action).__name__}")

    # -- drop-in files ----------------------------------------------------

    def _write(self, a: DropInWrite, *, host, key, user, port) -> ExecOutcome:
        cmd = f"write {a.path} ({len(a.content)} bytes) via 'sudo -n tee'"
        if not dir_allowed(a.path):
            return ExecOutcome(applied=False, resolved_command=cmd,
                               blocked_reason=f"path not under an allowlisted config dir: {a.path}")
        out, reason = self._ex.run_one(host, ["sudo", "-n", "tee", a.path],
                                       key=key, user=user, port=port, input=a.content)
        if out is None:
            return ExecOutcome(applied=False, resolved_command=cmd, blocked_reason=reason)
        if out.exit_code != 0:
            return ExecOutcome(applied=False, resolved_command=cmd, result=out,
                               blocked_reason=f"write failed (exit {out.exit_code})")

        def _rollback():
            self._ex.run_one(host, ["sudo", "-n", "rm", "-f", a.path],
                             key=key, user=user, port=port)

        # validate first (e.g. `nginx -t`), then reload — rolling the file back
        # (deleting it) if either step fails, so a bad drop-in never stays.
        for step, argv in (("validate", a.validate), ("reload/validate", a.reload)):
            if not argv:
                continue
            sout, sreason = self._ex.run_one(host, list(argv), key=key, user=user, port=port)
            if sout is None or sout.exit_code != 0:
                _rollback()
                code = "n/a" if sout is None else sout.exit_code
                detail = sreason or f"{step} failed (exit {code})"
                return ExecOutcome(applied=False, resolved_command=cmd, result=sout,
                                   blocked_reason=f"{detail}; drop-in removed")
        return ExecOutcome(applied=True, resolved_command=cmd, result=out)

    def _remove(self, a: DropInRemove, *, host, key, user, port) -> ExecOutcome:
        cmd = f"remove {a.path}"
        if not dir_allowed(a.path):
            return ExecOutcome(applied=False, resolved_command=cmd,
                               blocked_reason=f"path not under an allowlisted config dir: {a.path}")
        out, reason = self._ex.run_one(host, ["sudo", "-n", "rm", "-f", a.path],
                                       key=key, user=user, port=port)
        if out is None:
            return ExecOutcome(applied=False, resolved_command=cmd, blocked_reason=reason)
        if a.reload and out.exit_code == 0:
            self._ex.run_one(host, list(a.reload), key=key, user=user, port=port)
        ok = out.exit_code == 0
        return ExecOutcome(applied=ok, resolved_command=cmd, result=out,
                           blocked_reason=None if ok else f"remove failed (exit {out.exit_code})")

    # -- in-place marker-block edits -------------------------------------

    def _edit(self, a, *, host, key, user, port) -> ExecOutcome:
        label = f"edit {a.path} [block {a.marker}]"
        if not edit_path_allowed(a.path):
            return ExecOutcome(applied=False, resolved_command=label,
                               blocked_reason=f"path not in the allowlisted edit set: {a.path}")
        out, reason = self._ex.run_one(host, ["sudo", "-n", "cat", a.path],
                                       key=key, user=user, port=port)
        if out is None:
            return ExecOutcome(applied=False, resolved_command=label, blocked_reason=reason)
        if out.exit_code != 0:
            return ExecOutcome(applied=False, resolved_command=label, result=out,
                               blocked_reason=f"could not read {a.path} (exit {out.exit_code})")
        current = out.stdout
        new = (ensure_block(current, a.marker, a.body) if isinstance(a, ConfigBlockWrite)
               else remove_block(current, a.marker))
        diff = "".join(difflib.unified_diff(
            current.splitlines(keepends=True), new.splitlines(keepends=True),
            fromfile=a.path, tofile=f"{a.path} (proposed)"))
        if new == current:
            return ExecOutcome(applied=True, resolved_command=label, result=out,
                               diff="")        # idempotent: already in the desired state
        return self._write_validated(a, new, label=label, diff=diff,
                                     host=host, key=key, user=user, port=port)

    def _write_validated(self, a, new_content, *, label, diff,
                         host, key, user, port) -> ExecOutcome:
        bak = a.path + ".ai-defense.bak"

        def _run(argv, **kw):
            return self._ex.run_one(host, argv, key=key, user=user, port=port, **kw)

        def _restore():
            _run(["sudo", "-n", "cp", bak, a.path])

        b_out, b_reason = _run(["sudo", "-n", "cp", a.path, bak])        # back up first
        if b_out is None or b_out.exit_code != 0:
            why = b_reason or f"backup failed (exit {b_out.exit_code})"
            return ExecOutcome(applied=False, resolved_command=label, diff=diff, blocked_reason=why)
        w_out, w_reason = _run(["sudo", "-n", "tee", a.path], input=new_content)
        if w_out is None or w_out.exit_code != 0:
            _restore()
            why = w_reason or f"write failed (exit {w_out.exit_code}); restored"
            return ExecOutcome(applied=False, resolved_command=label, diff=diff, blocked_reason=why)
        if a.validate:
            v_out, v_reason = _run(list(a.validate))
            if v_out is None or v_out.exit_code != 0:
                _restore()
                detail = v_reason or f"validation failed (exit {v_out.exit_code})"
                return ExecOutcome(applied=False, resolved_command=label, diff=diff, result=v_out,
                                   blocked_reason=f"{detail}; restored from backup")
        if a.reload:
            _run(list(a.reload))
        return ExecOutcome(applied=True, resolved_command=label, result=w_out, diff=diff)
