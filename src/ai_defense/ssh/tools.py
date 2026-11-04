"""SSH-backed tools, registered into the toolset as dispatchable Executors.

A factory binds an ``SSHExecutor`` to a catalog template and returns an Executor
closure matching the toolset protocol ``(params, *, resolve_secret) -> ToolResult``.

The intent names only ``asset_id`` (plus the package) — host, port, user and the
key's vault reference are resolved from the **trusted asset registry**, never
from planner-supplied text, so a command can never be aimed at an arbitrary host
or key. The closure then fetches the key via ``resolve_secret`` (vault, at call
time), runs the template (dry-run first), and reports a result carrying a
rollback action.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from ..registry.assets import AssetRegistry, ConnectionInfo
from ..toolset.intents import ToolResult
from ..toolset.registry import ToolCapability, ToolSpec
from .catalog import PRE_RESTORE_SUFFIX, AptSourcesCodenameSwap, action_primitive_kind
from .config_exec import ConfigExecutor
from .executor import SSHExecutor
from .hardening import PrimitiveKind, RollbackAction

SECURITY_UPDATE_TOOL = "patch.apply_security_update"
MITIGATION_TOOL = "mitigation.apply_hardening"
OS_UPGRADE_TOOL = "os.release_upgrade"
BACKUP_DIFF_TOOL = "config.backup_diff"
RESTORE_BACKUP_TOOL = "config.restore_backup"

# do-release-upgrade runs far longer than the default 60s command timeout.
OS_UPGRADE_TIMEOUT_S = 3600

ConnectionResolver = Callable[[str], ConnectionInfo]


def registry_connection_resolver(
    registry: AssetRegistry, *, clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> ConnectionResolver:
    """Resolve an asset's SSH ConnectionInfo from the registry, re-checking that
    the asset is itself registered and authorized (so the actual connection
    target is always an authorized asset, not just whatever text was passed)."""

    def resolve(asset_id: str) -> ConnectionInfo:
        asset = registry.require_authorized(asset_id, clock())  # raises if unauthorized
        if asset.connection is None:
            raise KeyError(f"asset {asset_id} has no connection info")
        return asset.connection

    return resolve


def make_security_update_tool(
    executor: SSHExecutor,
    connection_resolver: ConnectionResolver,
    template_name: str = "apt.install_security",
) -> ToolSpec:
    """Build the ``patch.apply_security_update`` tool (capability=MUTATING).

    Params: ``asset_id`` (the target host; its connection is resolved from the
    registry), ``package`` (the package to upgrade), and optional ``snapshot_id``
    (the protective snapshot taken before the change, used for rollback).
    """

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        asset_id = params["asset_id"]
        package = params["package"]
        conn = connection_resolver(asset_id)       # host/user/port/key_ref from registry
        key = resolve_secret(conn.key_ref)          # key value from the vault

        outcome = executor.run_template(
            conn.host, template_name, {"package": package}, key=key,
            user=conn.user, port=conn.port, dry_run_first=True,
        )

        rollback = RollbackAction(
            kind=PrimitiveKind.PACKAGE,
            description=(
                f"restore '{package}' on {asset_id}: reinstall the prior version, "
                f"or restore pre-change snapshot {params.get('snapshot_id', '<none>')}"
            ),
            payload={"asset_id": asset_id, "package": package,
                     "snapshot_id": params.get("snapshot_id")},
        )

        if not outcome.applied:
            return ToolResult(
                ok=False, tool=SECURITY_UPDATE_TOOL,
                summary=f"not applied: {outcome.blocked_reason}",
                data={"blocked_reason": outcome.blocked_reason,
                      "dry_run_exit": outcome.dry_run.exit_code if outcome.dry_run else None},
                resolved_command=outcome.resolved_command,
            )

        res = outcome.result
        ok = res is not None and res.exit_code == 0
        exit_str = res.exit_code if res else "?"
        summary = (f"{package} upgraded on {asset_id}" if ok
                   else f"{package} upgrade failed on {asset_id} (exit {exit_str})")
        return ToolResult(
            ok=ok, tool=SECURITY_UPDATE_TOOL,
            summary=summary,
            data={
                "asset_id": asset_id,
                "exit_code": res.exit_code if res else None,
                "stdout": res.stdout if res else "",
                "stderr": res.stderr if res else "",
                "dry_run_exit": outcome.dry_run.exit_code if outcome.dry_run else None,
                "rollback": {"kind": rollback.kind.value, "description": rollback.description,
                             "payload": rollback.payload},
            },
            resolved_command=outcome.resolved_command,
        )

    return ToolSpec(
        name=SECURITY_UPDATE_TOOL,
        schema={
            "type": "object",
            "required": ["asset_id", "package"],
            "properties": {
                "asset_id": {"type": "string"},
                "package": {"type": "string"},
                "snapshot_id": {"type": "string"},
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
    )


@dataclass(frozen=True)
class _MitigationCommand:
    template: str                 # allowlisted catalog template to apply
    rollback_template: str        # allowlisted catalog template to undo it
    description: str


# Allowlisted hardening mitigations the toolset will apply, keyed by the
# ``mitigation_id`` named in ``vuln.mitigations``. DEFAULT DENY: an id not here is
# refused, so the planner can never ask for an arbitrary command (rule #3/#5).
_MITIGATIONS: dict[str, _MitigationCommand] = {
    "pwnkit-pkexec-suid": _MitigationCommand(
        template="harden.disable_pkexec_suid",
        rollback_template="harden.restore_pkexec_suid",
        description="remove setuid from /usr/bin/pkexec (reverse: restore 4755)",
    ),
}


def make_mitigation_tool(
    executor: SSHExecutor, connection_resolver: ConnectionResolver,
    mitigations: dict[str, _MitigationCommand] | None = None, *,
    config_executor=None, config_actions: dict | None = None,
) -> ToolSpec:
    """Build the ``mitigation.apply_hardening`` tool (capability=MUTATING).

    Params: ``asset_id`` (connection resolved from the registry) and
    ``mitigation_id`` (must be in the allowlisted ``mitigations`` map). The
    mitigation's ``template`` names a reviewed action: a **command** in the
    catalog (run dry-run-first) or a **config drop-in** in ``config_actions`` (run
    via ``config_executor``, which writes/validates/reloads and rolls back on
    failure). Either way the planner supplies only an id, never a command, and a
    rollback action is recorded.

    ``mitigations`` is the id -> command map (built by the composition root from
    the loaded registry); it defaults to the built-ins so the tool is usable
    without a configured folder."""
    catalogue = mitigations if mitigations is not None else _MITIGATIONS
    configs = config_actions or {}

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        asset_id = params["asset_id"]
        mitigation_id = params["mitigation_id"]
        reverse = bool(params.get("reverse"))
        mc = catalogue.get(mitigation_id)
        if mc is None:
            return ToolResult(
                ok=False, tool=MITIGATION_TOOL,
                summary=f"unknown mitigation (not allowlisted): {mitigation_id}",
                data={"mitigation_id": mitigation_id})

        # reverse runs the recorded rollback action; its own undo is to re-apply.
        action_name = mc.rollback_template if reverse else mc.template
        undo_name = mc.template if reverse else mc.rollback_template
        verb = "reverted" if reverse else "applied"

        conn = connection_resolver(asset_id)       # host/user/port/key_ref from registry
        key = resolve_secret(conn.key_ref)          # key value from the vault

        is_config = action_name in configs
        if is_config:
            if config_executor is None:
                return ToolResult(ok=False, tool=MITIGATION_TOOL,
                                  summary="config mitigations are not wired in this engine")
            outcome = config_executor.apply(configs[action_name], host=conn.host, key=key,
                                             user=conn.user, port=conn.port)
        else:
            outcome = executor.run_template(
                conn.host, action_name, {}, key=key,
                user=conn.user, port=conn.port, dry_run_first=True,
            )
        rollback_kind = (action_primitive_kind(configs[action_name]) if is_config
                         else PrimitiveKind.FILE_PERM)
        rollback = RollbackAction(
            kind=rollback_kind,
            description=(f"re-apply mitigation on {asset_id}: {mc.description}" if reverse
                        else f"revert mitigation on {asset_id}: {mc.description}"),
            payload={"asset_id": asset_id, "rollback_template": undo_name},
        )

        if not outcome.applied:
            return ToolResult(
                ok=False, tool=MITIGATION_TOOL,
                summary=f"not {verb}: {outcome.blocked_reason}",
                data={"blocked_reason": outcome.blocked_reason,
                      "dry_run_exit": outcome.dry_run.exit_code if outcome.dry_run else None,
                      "diff": outcome.diff},
                resolved_command=outcome.resolved_command)

        res = outcome.result
        ok = res is not None and res.exit_code == 0
        return ToolResult(
            ok=ok, tool=MITIGATION_TOOL,
            summary=(f"mitigation '{mitigation_id}' {verb} on {asset_id}" if ok
                     else f"mitigation '{mitigation_id}' {verb[:-2] if reverse else 'apply'}"
                          f" failed on {asset_id}"),
            data={
                "asset_id": asset_id, "mitigation_id": mitigation_id, "reverse": reverse,
                "exit_code": res.exit_code if res else None,
                "stdout": res.stdout if res else "",
                "stderr": res.stderr if res else "",
                "diff": outcome.diff,
                "rollback": {"kind": rollback.kind.value,
                             "description": rollback.description,
                             "payload": rollback.payload},
            },
            resolved_command=outcome.resolved_command)

    return ToolSpec(
        name=MITIGATION_TOOL,
        schema={
            "type": "object",
            "required": ["asset_id", "mitigation_id"],
            "properties": {
                "asset_id": {"type": "string"},
                "mitigation_id": {"type": "string"},
                "reverse": {"type": "boolean"},   # run the recorded rollback action
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
    )


_RESTORE_SCHEMA = {
    "type": "object",
    "required": ["asset_id", "path"],
    "properties": {"asset_id": {"type": "string"}, "path": {"type": "string"}},
}


def make_backup_diff_tool(connection_resolver: ConnectionResolver,
                          config_executor: ConfigExecutor) -> ToolSpec:
    """``config.backup_diff`` (READ_ONLY): what restoring an allowlisted file from
    its in-place-edit backup would change. Lets the approver see the diff before
    approving ``config.restore_backup``."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        asset_id, path = params["asset_id"], params["path"]
        conn = connection_resolver(asset_id)
        out = config_executor.backup_diff(path, host=conn.host, key=resolve_secret(conn.key_ref),
                                          user=conn.user, port=conn.port)
        if not out.applied:
            return ToolResult(ok=False, tool=BACKUP_DIFF_TOOL,
                              summary=f"cannot preview restore of {path} on {asset_id}: "
                                      f"{out.blocked_reason}",
                              data={"asset_id": asset_id, "path": path,
                                    "blocked_reason": out.blocked_reason},
                              resolved_command=out.resolved_command)
        same = out.diff == ""
        return ToolResult(ok=True, tool=BACKUP_DIFF_TOOL,
                          summary=(f"{path} on {asset_id} already matches its backup" if same
                                   else f"restoring {path} on {asset_id} would apply this diff"),
                          data={"asset_id": asset_id, "path": path, "diff": out.diff,
                                "identical": same},
                          resolved_command=out.resolved_command)

    return ToolSpec(name=BACKUP_DIFF_TOOL, schema=_RESTORE_SCHEMA, executor=_execute,
                    capability=ToolCapability.READ_ONLY)


def make_restore_backup_tool(connection_resolver: ConnectionResolver,
                             config_executor: ConfigExecutor) -> ToolSpec:
    """``config.restore_backup`` (MUTATING): put an allowlisted file back to the
    backup its last in-place edit left (``<path>.ai-defense.bak``). The path must
    be on ALLOWED_EDIT_PATHS; the replaced content is saved first, and put back if
    the path's validator (e.g. ``sshd -t``) rejects the restored file."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        asset_id, path = params["asset_id"], params["path"]
        conn = connection_resolver(asset_id)
        out = config_executor.restore_backup(path, host=conn.host,
                                             key=resolve_secret(conn.key_ref),
                                             user=conn.user, port=conn.port)
        res = out.result
        base = {"asset_id": asset_id, "path": path, "diff": out.diff,
                "stdout": res.stdout if res else "", "stderr": res.stderr if res else ""}
        if not out.applied:
            return ToolResult(ok=False, tool=RESTORE_BACKUP_TOOL,
                              summary=f"{path} not restored on {asset_id}: {out.blocked_reason}",
                              data={**base, "blocked_reason": out.blocked_reason},
                              resolved_command=out.resolved_command)
        pre = path + PRE_RESTORE_SUFFIX
        rollback = RollbackAction(
            kind=PrimitiveKind.CONFIG_EDIT,
            description=f"the replaced {path} is kept at {pre} on {asset_id}",
            payload={"asset_id": asset_id, "path": path, "saved_copy": pre})
        return ToolResult(
            ok=True, tool=RESTORE_BACKUP_TOOL,
            summary=(f"{path} on {asset_id} already matched its backup; nothing changed"
                     if out.diff == "" else f"{path} restored from backup on {asset_id}"),
            data={**base, "rollback": {"kind": rollback.kind.value,
                                       "description": rollback.description,
                                       "payload": rollback.payload}},
            resolved_command=out.resolved_command)

    return ToolSpec(name=RESTORE_BACKUP_TOOL, schema=_RESTORE_SCHEMA, executor=_execute,
                    capability=ToolCapability.MUTATING)


def _reboot_and_classify(
    executor: SSHExecutor, conn: ConnectionInfo, key, asset_id: str, target: str | None,
    rb_json: dict, resolved_command: str | None, upgrade_exit: int | None,
) -> ToolResult:
    """Shared final step for both distro paths: reboot into the upgraded system,
    and classify the outcome carefully — the reboot severs the SSH session, so
    "the command didn't return a clean 0" is normal, not failure:
      * transport raised (connection dropped)        -> rebooting (success)
      * exit code <= 0 (0 = clean; -1 = channel closed as the host went down;
        paramiko's recv_exit_status returns -1, it does NOT raise)
                                                       -> rebooting (success)
      * applied=False (e.g. refused before running)  -> NOT issued (failure)
      * POSITIVE exit with a live connection (e.g. sudo refused)
                                                       -> NOT issued (failure)
    On a genuine "not issued", return ok=False so the workflow halts with the
    snapshot retained rather than claiming a host rebooted when it didn't."""
    try:
        rb = executor.run_template(conn.host, "os.reboot", {}, key=key,
                                   user=conn.user, port=conn.port, dry_run_first=False)
    except Exception:  # noqa: BLE001 - reboot severs the connection; that's success
        rb = None
    reboot_failed = None
    if rb is not None:
        if not rb.applied:
            reboot_failed = f"reboot was refused before running ({rb.blocked_reason})"
        elif rb.result is not None and rb.result.exit_code > 0:
            reboot_failed = f"reboot command returned exit {rb.result.exit_code}"
    if reboot_failed:
        return ToolResult(
            ok=False, tool=OS_UPGRADE_TOOL,
            summary=(f"release upgrade applied on {asset_id} but {reboot_failed}; "
                     "host NOT rebooted"),
            data={"asset_id": asset_id, "target_version": target,
                  "upgrade_exit": upgrade_exit, "reboot_issued": False, "rollback": rb_json},
            resolved_command=resolved_command)
    return ToolResult(
        ok=True, tool=OS_UPGRADE_TOOL,
        summary=(f"release upgrade applied on {asset_id}; reboot issued"
                 + (f" (target {target})" if target else "")),
        data={"asset_id": asset_id, "target_version": target,
              "upgrade_exit": upgrade_exit, "reboot_issued": True, "rollback": rb_json},
        resolved_command=resolved_command)


def make_os_upgrade_tool(
    executor: SSHExecutor, connection_resolver: ConnectionResolver, *,
    config_executor: ConfigExecutor | None = None,
) -> ToolSpec:
    """Build the ``os.release_upgrade`` tool (capability=MUTATING).

    The mutating core of the OS_UPGRADE workflow: drive an in-place release
    upgrade and reboot into it, as one approved action. Params: ``asset_id`` (conn
    resolved from the registry), ``distro`` ("ubuntu" default, or "debian"),
    optional ``target_version`` (for the summary and the workflow's post-reboot
    health check) and ``snapshot_id`` (the mandatory pre-upgrade snapshot, recorded
    as the rollback — a dist-upgrade can't be undone in place, so restoring the
    snapshot IS the rollback). For Debian, ``old_codename``/``new_codename`` are
    also required — these come from the reviewed release table via the workflow,
    never from planner text (the MCP-facing ``os_upgrade`` tool never exposes them).

    Ubuntu sequence: ``do-release-upgrade -c`` (dry-run: is an upgrade available?
    changes nothing) → ``do-release-upgrade`` → ``systemctl reboot``.

    Debian sequence (no single wrapper tool exists): a read-only check that no
    third-party source under ``/etc/apt/sources.list.d/`` still names the old
    codename (refuse rather than upgrade against inconsistent repos) → rewrite
    ``/etc/apt/sources.list`` (old codename → new, backed up/diffed/restored on
    failure, validated by ``apt-get update`` — needs ``config_executor``) →
    ``apt-get full-upgrade`` (dry-run `--simulate` first) → ``systemctl reboot``.

    Either way the reboot drops the SSH session; that is expected and counts as
    "reboot issued" — the workflow then polls for the host to come back.
    Post-reboot reconnect/health/re-scan are read-only and live in the workflow,
    not here."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        asset_id = params["asset_id"]
        target = params.get("target_version")
        snapshot_id = params.get("snapshot_id")
        distro = (params.get("distro") or "ubuntu").lower()
        conn = connection_resolver(asset_id)
        key = resolve_secret(conn.key_ref)

        rollback = RollbackAction(
            kind=PrimitiveKind.OS_UPGRADE,
            description=(f"restore pre-upgrade snapshot {snapshot_id or '<none>'} on "
                        f"{asset_id} (an in-place dist-upgrade cannot be reverted in place)"),
            payload={"asset_id": asset_id, "snapshot_id": snapshot_id},
        )
        rb_json = {"kind": rollback.kind.value, "description": rollback.description,
                   "payload": rollback.payload}

        if distro == "debian":
            old_codename = params.get("old_codename")
            new_codename = params.get("new_codename")
            if not old_codename or not new_codename:
                return ToolResult(
                    ok=False, tool=OS_UPGRADE_TOOL,
                    summary=f"missing codename info for the Debian upgrade on {asset_id}",
                    data={"rollback": rb_json})
            if config_executor is None:
                return ToolResult(ok=False, tool=OS_UPGRADE_TOOL,
                                  summary="Debian upgrades are not wired in this engine")
            try:
                swap = AptSourcesCodenameSwap(
                    name="os.debian_sources_swap", path="/etc/apt/sources.list",
                    old_codename=old_codename, new_codename=new_codename,
                    validate=("sudo", "-n", "apt-get", "update"))
            except ValueError as exc:
                return ToolResult(ok=False, tool=OS_UPGRADE_TOOL,
                                  summary=f"refusing unsafe codename value: {exc}")

            # Read-only pre-check: a stale third-party source would leave the host
            # on an inconsistent mix of releases after full-upgrade (fail safe on
            # ambiguity rather than upgrade against it). Best-effort: this catches
            # the common one-repo-per-line .list format, not the newer deb822
            # .sources format.
            grep_out, _ = executor.run_one(
                conn.host, ["grep", "-rl", old_codename, "/etc/apt/sources.list.d/"],
                key=key, user=conn.user, port=conn.port)
            if grep_out is not None and grep_out.exit_code == 0 and grep_out.stdout.strip():
                return ToolResult(
                    ok=False, tool=OS_UPGRADE_TOOL,
                    summary=(f"third-party apt sources under /etc/apt/sources.list.d/ still "
                             f"reference '{old_codename}' on {asset_id}; update them first"),
                    data={"asset_id": asset_id, "stale_sources": grep_out.stdout.strip(),
                          "rollback": rb_json})

            swap_out = config_executor.apply(swap, host=conn.host, key=key,
                                             user=conn.user, port=conn.port)
            if not swap_out.applied:
                v = swap_out.result
                return ToolResult(
                    ok=False, tool=OS_UPGRADE_TOOL,
                    summary=f"sources.list rewrite failed on {asset_id}: {swap_out.blocked_reason}",
                    data={"blocked_reason": swap_out.blocked_reason, "diff": swap_out.diff,
                          "stdout": v.stdout if v else "", "stderr": v.stderr if v else "",
                          "rollback": rb_json},
                    resolved_command=swap_out.resolved_command)

            up = executor.run_template(conn.host, "apt.full_upgrade", {}, key=key,
                                       user=conn.user, port=conn.port, dry_run_first=True,
                                       timeout=OS_UPGRADE_TIMEOUT_S)
            if not up.applied:
                return ToolResult(
                    ok=False, tool=OS_UPGRADE_TOOL,
                    summary=f"full-upgrade not applied on {asset_id}: {up.blocked_reason}",
                    data={"blocked_reason": up.blocked_reason,
                          "dry_run_exit": up.dry_run.exit_code if up.dry_run else None,
                          "sources_diff": swap_out.diff, "rollback": rb_json},
                    resolved_command=up.resolved_command)
            res = up.result
            if res is None or res.exit_code != 0:
                code = res.exit_code if res else "?"
                return ToolResult(
                    ok=False, tool=OS_UPGRADE_TOOL,
                    summary=f"full-upgrade command failed on {asset_id} (exit {code})",
                    data={"exit_code": res.exit_code if res else None,
                          "stderr": res.stderr if res else "", "rollback": rb_json},
                    resolved_command=up.resolved_command)
            return _reboot_and_classify(executor, conn, key, asset_id, target, rb_json,
                                        up.resolved_command, res.exit_code)

        # Ubuntu path (default). Dry-run `-c` first; long timeout since the real
        # upgrade can run for many minutes.
        up = executor.run_template(conn.host, "os.do_release_upgrade", {}, key=key,
                                   user=conn.user, port=conn.port, dry_run_first=True,
                                   timeout=OS_UPGRADE_TIMEOUT_S)
        if not up.applied:
            return ToolResult(
                ok=False, tool=OS_UPGRADE_TOOL,
                summary=f"release upgrade not applied on {asset_id}: {up.blocked_reason}",
                data={"blocked_reason": up.blocked_reason,
                      "dry_run_exit": up.dry_run.exit_code if up.dry_run else None,
                      "rollback": rb_json},
                resolved_command=up.resolved_command)
        res = up.result
        if res is None or res.exit_code != 0:
            code = res.exit_code if res else "?"
            return ToolResult(
                ok=False, tool=OS_UPGRADE_TOOL,
                summary=f"release upgrade command failed on {asset_id} (exit {code})",
                data={"exit_code": res.exit_code if res else None,
                      "stderr": res.stderr if res else "", "rollback": rb_json},
                resolved_command=up.resolved_command)
        return _reboot_and_classify(executor, conn, key, asset_id, target, rb_json,
                                    up.resolved_command, res.exit_code)

    return ToolSpec(
        name=OS_UPGRADE_TOOL,
        schema={
            "type": "object",
            "required": ["asset_id"],
            "properties": {
                "asset_id": {"type": "string"},
                "target_version": {"type": "string"},
                "snapshot_id": {"type": "string"},
                "distro": {"type": "string"},
                "old_codename": {"type": "string"},
                "new_codename": {"type": "string"},
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
    )
