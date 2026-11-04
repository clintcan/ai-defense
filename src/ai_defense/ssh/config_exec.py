"""Executor for managed config drop-ins (write/remove a file over SSH).

Every argv still goes through ``SSHExecutor.run_one`` (denylist + output cap). A
privileged write uses ``sudo -n tee <path>`` fed the body on stdin — no shell
redirection, no sftp. Applying then runs the op's ``reload`` (which also
validates, e.g. ``sysctl -p <file>``) and, if that fails, **removes the drop-in**
so the host is left exactly as it was. Returns an :class:`ExecOutcome`, the same
shape ``SSHExecutor.run_template`` returns, so the mitigation tool treats command
and config actions uniformly.
"""

from __future__ import annotations

from .catalog import DropInRemove, DropInWrite, dir_allowed
from .executor import ExecOutcome, SSHExecutor


class ConfigExecutor:
    def __init__(self, executor: SSHExecutor) -> None:
        self._ex = executor

    def apply(self, action: DropInWrite | DropInRemove, *, host: str, key: str,
              user: str = "root", port: int = 22) -> ExecOutcome:
        if isinstance(action, DropInWrite):
            return self._write(action, host=host, key=key, user=user, port=port)
        if isinstance(action, DropInRemove):
            return self._remove(action, host=host, key=key, user=user, port=port)
        return ExecOutcome(applied=False, resolved_command="",
                           blocked_reason=f"unknown config action: {type(action).__name__}")

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
        # reload doubles as validation; on failure, roll back by removing the file.
        if a.reload:
            rout, rreason = self._ex.run_one(host, list(a.reload), key=key, user=user, port=port)
            if rout is None or rout.exit_code != 0:
                self._ex.run_one(host, ["sudo", "-n", "rm", "-f", a.path],
                                 key=key, user=user, port=port)   # rollback
                detail = rreason or f"reload/validate failed (exit {rout.exit_code})"
                return ExecOutcome(applied=False, resolved_command=cmd, result=rout,
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
