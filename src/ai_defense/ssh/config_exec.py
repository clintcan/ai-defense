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
- **Debian codename swap** (``AptSourcesCodenameSwap``): the same backup/diff/
  validate/restore dance, but for an in-place OS upgrade's ``/etc/apt/sources.list``
  rewrite (old release codename -> new), validated with ``apt-get update``.
  Refuses (fail-safe) rather than guesses if the file names neither codename.

All paths are checked against the allowlists (default deny). Returns an
:class:`ExecOutcome` so the mitigation tool treats every action kind uniformly.
"""

from __future__ import annotations

import difflib

from .catalog import (
    BACKUP_SUFFIX,
    PRE_RESTORE_SUFFIX,
    RESTORE_CHECKS,
    AptSourcesCodenameSwap,
    ConfigBlockRemove,
    ConfigBlockWrite,
    DropInRemove,
    DropInWrite,
    dir_allowed,
    edit_path_allowed,
)
from .catalog.firewall import FirewallRule
from .catalog.modules import ModuleBlacklist, ModuleUnblacklist
from .catalog.services import ServiceStateChange
from .config_edit import codename_present, ensure_block, remove_block, swap_codename
from .executor import ExecOutcome, SSHExecutor
from .hardening import (
    HARDENING_MODULE_ALLOWLIST,
    FirewallAction,
    FirewallChange,
    ServiceAction,
)

_FW_VERB = {
    "allow": FirewallAction.ALLOW,
    "deny": FirewallAction.DENY,
    "restrict_source": FirewallAction.RESTRICT_SOURCE,
    "remove_rule": FirewallAction.REMOVE_RULE,
}


class ConfigExecutor:
    def __init__(self, executor: SSHExecutor, *, mgmt_sources: tuple[str, ...] = ()) -> None:
        self._ex = executor
        self._mgmt_sources = tuple(mgmt_sources)   # CIDRs the lockout guard protects

    def apply(self, action, *, host: str, key: str,
              user: str = "root", port: int = 22) -> ExecOutcome:
        if isinstance(action, DropInWrite):
            return self._write(action, host=host, key=key, user=user, port=port)
        if isinstance(action, DropInRemove):
            return self._remove(action, host=host, key=key, user=user, port=port)
        if isinstance(action, (ConfigBlockWrite, ConfigBlockRemove, AptSourcesCodenameSwap)):
            return self._edit(action, host=host, key=key, user=user, port=port)
        if isinstance(action, (ModuleBlacklist, ModuleUnblacklist)):
            return self._module(action, host=host, key=key, user=user, port=port)
        if isinstance(action, ServiceStateChange):
            return self._service(action, host=host, key=key, user=user, port=port)
        if isinstance(action, FirewallRule):
            return self._firewall(action, host=host, key=key, user=user, port=port)
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

    # -- in-place marker-block edits & the Debian codename swap -----------

    def _edit(self, a, *, host, key, user, port) -> ExecOutcome:
        is_swap = isinstance(a, AptSourcesCodenameSwap)
        label = (f"edit {a.path} [codename {a.old_codename}->{a.new_codename}]" if is_swap
                 else f"edit {a.path} [block {a.marker}]")
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
        if is_swap:
            # Fail safe on ambiguity (CLAUDE.md #7): if the file names neither the
            # old nor the new codename, don't guess — a symbolic-name sources.list
            # (`stable`/`oldstable`) needs no edit at all, but we can't tell that
            # apart from a genuinely unexpected layout from the codenames alone.
            if not (codename_present(current, a.old_codename)
                    or codename_present(current, a.new_codename)):
                return ExecOutcome(
                    applied=False, resolved_command=label,
                    blocked_reason=(f"neither '{a.old_codename}' nor '{a.new_codename}' found "
                                    f"in {a.path} — if it uses symbolic release names "
                                    f"(stable/oldstable) no edit is needed; verify and retry, "
                                    f"or edit sources.list manually first"))
            new = swap_codename(current, a.old_codename, a.new_codename)
        else:
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
        bak = a.path + BACKUP_SUFFIX

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

    # -- restore an allowlisted file from its BACKUP_SUFFIX copy ---------

    def _read_with_backup(self, path, *, host, key, user, port):
        """(current, backup, refusal) — refusal is set if either can't be read."""
        def cat(p):
            return self._ex.run_one(host, ["sudo", "-n", "cat", p], key=key, user=user, port=port)
        out, reason = cat(path)
        if out is None or out.exit_code != 0:
            return None, None, reason or f"could not read {path} (exit {out.exit_code})"
        bout, breason = cat(path + BACKUP_SUFFIX)
        if bout is None or bout.exit_code != 0:
            return out.stdout, None, (breason or f"no backup at {path}{BACKUP_SUFFIX} "
                                                f"(exit {bout.exit_code})")
        return out.stdout, bout.stdout, None

    @staticmethod
    def _restore_diff(path, current, backup) -> str:
        return "".join(difflib.unified_diff(
            current.splitlines(keepends=True), backup.splitlines(keepends=True),
            fromfile=path, tofile=f"{path} (restored from {path}{BACKUP_SUFFIX})"))

    def backup_diff(self, path: str, *, host: str, key: str,
                    user: str = "root", port: int = 22) -> ExecOutcome:
        """Read-only: the diff a restore of ``path`` would make. Changes nothing."""
        label = f"diff {path} against {path}{BACKUP_SUFFIX}"
        if not edit_path_allowed(path):
            return ExecOutcome(applied=False, resolved_command=label,
                               blocked_reason=f"path not in the allowlisted edit set: {path}")
        current, backup, why = self._read_with_backup(path, host=host, key=key,
                                                      user=user, port=port)
        if why:
            return ExecOutcome(applied=False, resolved_command=label, blocked_reason=why)
        return ExecOutcome(applied=True, resolved_command=label,
                           diff=self._restore_diff(path, current, backup))

    def restore_backup(self, path: str, *, host: str, key: str,
                       user: str = "root", port: int = 22) -> ExecOutcome:
        """Put ``path`` back to its BACKUP_SUFFIX copy. The replaced content is
        kept at PRE_RESTORE_SUFFIX first, and is put back if the path's
        RESTORE_CHECKS validator rejects the restored file."""
        label = f"restore {path} from {path}{BACKUP_SUFFIX}"
        if not edit_path_allowed(path):
            return ExecOutcome(applied=False, resolved_command=label,
                               blocked_reason=f"path not in the allowlisted edit set: {path}")
        current, backup, why = self._read_with_backup(path, host=host, key=key,
                                                      user=user, port=port)
        if why:
            return ExecOutcome(applied=False, resolved_command=label, blocked_reason=why)
        if backup == current:
            return ExecOutcome(applied=True, resolved_command=label, diff="")   # idempotent
        diff = self._restore_diff(path, current, backup)

        def _run(argv):
            return self._ex.run_one(host, argv, key=key, user=user, port=port)

        pre = path + PRE_RESTORE_SUFFIX
        p_out, p_reason = _run(["sudo", "-n", "cp", path, pre])
        if p_out is None or p_out.exit_code != 0:
            why = p_reason or f"could not save current file (exit {p_out.exit_code})"
            return ExecOutcome(applied=False, resolved_command=label, diff=diff,
                               blocked_reason=f"{why}; nothing changed")
        c_out, c_reason = _run(["sudo", "-n", "cp", path + BACKUP_SUFFIX, path])
        if c_out is None or c_out.exit_code != 0:
            _run(["sudo", "-n", "cp", pre, path])
            why = c_reason or f"copy failed (exit {c_out.exit_code})"
            return ExecOutcome(applied=False, resolved_command=label, diff=diff,
                               blocked_reason=f"{why}; original put back")
        validate, reload = RESTORE_CHECKS.get(path, ((), ()))
        if validate:
            v_out, v_reason = _run(list(validate))
            if v_out is None or v_out.exit_code != 0:
                _run(["sudo", "-n", "cp", pre, path])
                why = v_reason or f"validation failed (exit {v_out.exit_code})"
                return ExecOutcome(applied=False, resolved_command=label, diff=diff,
                                   result=v_out, blocked_reason=f"{why}; original put back")
        if reload:
            _run(list(reload))
        return ExecOutcome(applied=True, resolved_command=label, result=c_out, diff=diff)

    # -- kernel modules ---------------------------------------------------

    def _module(self, a, *, host, key, user, port) -> ExecOutcome:
        # Defense in depth: re-check the allowlist even though it was verified at
        # import — a reviewed action can never blacklist an arbitrary module.
        if a.module not in HARDENING_MODULE_ALLOWLIST:
            return ExecOutcome(applied=False, resolved_command=f"module {a.module}",
                               blocked_reason=f"module not on the hardening allowlist: {a.module}")
        if isinstance(a, ModuleUnblacklist):
            cmd = f"un-blacklist {a.module} (remove {a.path})"
            out, reason = self._ex.run_one(host, ["sudo", "-n", "rm", "-f", a.path],
                                           key=key, user=user, port=port)
            if out is None:
                return ExecOutcome(applied=False, resolved_command=cmd, blocked_reason=reason)
            ok = out.exit_code == 0
            why = None if ok else f"remove failed (exit {out.exit_code})"
            return ExecOutcome(applied=ok, resolved_command=cmd, result=out, blocked_reason=why)
        # ModuleBlacklist: write the drop-in, then unload at runtime (best-effort).
        cmd = f"blacklist {a.module} ({a.path})"
        content = (f"# AI Defense: disable kernel module {a.module} (attack-surface reduction)\n"
                   f"blacklist {a.module}\n"
                   f"install {a.module} /bin/true\n")
        out, reason = self._ex.run_one(host, ["sudo", "-n", "tee", a.path],
                                       key=key, user=user, port=port, input=content)
        if out is None:
            return ExecOutcome(applied=False, resolved_command=cmd, blocked_reason=reason)
        if out.exit_code != 0:
            return ExecOutcome(applied=False, resolved_command=cmd, result=out,
                               blocked_reason=f"write failed (exit {out.exit_code})")
        # Runtime unload: a module in use can't be removed now, but the drop-in
        # already blocks it at next boot — report, don't roll back.
        u_out, _ = self._ex.run_one(host, ["sudo", "-n", "modprobe", "-r", a.module],
                                    key=key, user=user, port=port)
        note = None if (u_out is not None and u_out.exit_code == 0) else \
            "blacklist persisted; runtime unload deferred (module in use or absent)"
        return ExecOutcome(applied=True, resolved_command=cmd, result=out, diff=note)

    # -- services ---------------------------------------------------------

    def _service(self, a, *, host, key, user, port) -> ExecOutcome:
        cmd = f"systemctl {a.action.value} {a.unit}"
        if a.is_blocked():
            return ExecOutcome(applied=False, resolved_command=cmd,
                               blocked_reason=f"protected unit — refused: {a.unit}")
        argv_by_action = {
            ServiceAction.DISABLE: ["systemctl", "disable", "--now", a.unit],
            ServiceAction.MASK: ["systemctl", "mask", a.unit],
            ServiceAction.ENABLE: ["systemctl", "enable", "--now", a.unit],
        }
        tail = argv_by_action.get(a.action)
        if tail is None:        # UNMASK / START / STOP not exposed as catalog actions
            return ExecOutcome(applied=False, resolved_command=cmd,
                               blocked_reason=f"unsupported service action: {a.action.value}")
        out, reason = self._ex.run_one(host, ["sudo", "-n", *tail],
                                       key=key, user=user, port=port)
        if out is None:
            return ExecOutcome(applied=False, resolved_command=cmd, blocked_reason=reason)
        ok = out.exit_code == 0
        return ExecOutcome(applied=ok, resolved_command=cmd, result=out,
                           blocked_reason=None if ok else f"{cmd} failed (exit {out.exit_code})")

    # -- firewall rules ---------------------------------------------------

    def _firewall(self, a: FirewallRule, *, host, key, user, port) -> ExecOutcome:
        label = f"ufw {a.action} {a.port}/{a.proto}"

        def _run(argv):
            return self._ex.run_one(host, argv, key=key, user=user, port=port)

        # Lockout guard: never apply a rule that would cut our own management SSH.
        change = FirewallChange(action=_FW_VERB[a.action], port=a.port,
                                proto=a.proto, sources=a.sources)
        if change.locks_out_management(port, self._mgmt_sources):
            return ExecOutcome(applied=False, resolved_command=label,
                               blocked_reason=f"lockout guard: refuses a rule that would cut "
                                              f"management SSH (port {port})")
        apply_argvs = self._ufw_argvs(a)
        if apply_argvs is None:
            return ExecOutcome(applied=False, resolved_command=label,
                               blocked_reason=f"unsupported firewall action: {a.action}")
        last = None
        for argv in apply_argvs:
            out, reason = _run(argv)
            if out is None:
                return ExecOutcome(applied=False, resolved_command=label, blocked_reason=reason)
            if out.exit_code != 0:
                return ExecOutcome(applied=False, resolved_command=label, result=out,
                                   blocked_reason=f"{label} failed (exit {out.exit_code})")
            last = out

        # Timed auto-revert for rules that could cut access: schedule the undo,
        # then confirm management is still reachable; cancel on success, leave it
        # armed (so the rule self-reverts) on failure.
        undo = self._ufw_undo_argv(a)
        if undo is not None:
            unit = f"ai-defense-fw-revert-{a.port}-{a.proto}"
            _run(["sudo", "-n", "systemd-run", f"--on-active={a.revert_after_seconds}s",
                  f"--unit={unit}", "--description=ai-defense firewall auto-revert", *undo])
            h_out, _ = _run(["true"])       # does the management session still respond?
            if h_out is None or h_out.exit_code != 0:
                return ExecOutcome(applied=False, resolved_command=label,
                                   blocked_reason=f"post-apply health check failed; change "
                                                  f"auto-reverts in {a.revert_after_seconds}s")
            _run(["sudo", "-n", "systemctl", "stop", f"{unit}.timer"])   # confirmed -> rule sticks
            note = (f"auto-revert armed ({a.revert_after_seconds}s) then cancelled — "
                    f"management reachable")
            return ExecOutcome(applied=True, resolved_command=label, result=last, diff=note)
        return ExecOutcome(applied=True, resolved_command=label, result=last)

    @staticmethod
    def _ufw_argvs(a: FirewallRule) -> list[list[str]] | None:
        p = f"{a.port}/{a.proto}"
        if a.action == "deny":
            return [["sudo", "-n", "ufw", "deny", p]]
        if a.action == "allow" and not a.sources:
            return [["sudo", "-n", "ufw", "allow", p]]
        if a.action in ("allow", "restrict_source") and a.sources:
            return [["sudo", "-n", "ufw", "allow", "from", src, "to", "any",
                     "port", str(a.port), "proto", a.proto] for src in a.sources]
        if a.action == "remove_rule":
            return [["sudo", "-n", "ufw", "delete", a.removes, p]]
        return None

    @staticmethod
    def _ufw_undo_argv(a: FirewallRule) -> list[str] | None:
        # single command the auto-revert timer runs (as root via systemd-run, no sudo)
        p = f"{a.port}/{a.proto}"
        if a.action == "deny":
            return ["ufw", "delete", "deny", p]
        if a.action == "allow" and not a.sources:
            return ["ufw", "delete", "allow", p]
        return None     # multi-source / remove_rule: no single-command auto-undo
