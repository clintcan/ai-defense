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
from .catalog import action_primitive_kind
from .executor import SSHExecutor
from .hardening import PrimitiveKind, RollbackAction

SECURITY_UPDATE_TOOL = "patch.apply_security_update"
MITIGATION_TOOL = "mitigation.apply_hardening"
OS_UPGRADE_TOOL = "os.release_upgrade"

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


def make_os_upgrade_tool(
    executor: SSHExecutor, connection_resolver: ConnectionResolver,
) -> ToolSpec:
    """Build the ``os.release_upgrade`` tool (capability=MUTATING).

    The mutating core of the OS_UPGRADE workflow: drive an in-place Ubuntu release
    upgrade and reboot into it, as one approved action. Params: ``asset_id`` (conn
    resolved from the registry), optional ``target_version`` (for the summary and
    the workflow's post-reboot health check) and ``snapshot_id`` (the mandatory
    pre-upgrade snapshot, recorded as the rollback — a dist-upgrade can't be undone
    in place, so restoring the snapshot IS the rollback).

    Sequence: ``do-release-upgrade -c`` (dry-run: is an upgrade available? changes
    nothing) → ``do-release-upgrade`` → ``systemctl reboot``. The reboot drops the
    SSH session; that is expected and counts as "reboot issued" — the workflow then
    polls for the host to come back. Post-reboot reconnect/health/re-scan are
    read-only and live in the workflow, not here."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        asset_id = params["asset_id"]
        target = params.get("target_version")
        snapshot_id = params.get("snapshot_id")
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

        # 1. In-place release upgrade (dry-run `-c` first: is a new release available?).
        up = executor.run_template(conn.host, "os.do_release_upgrade", {}, key=key,
                                   user=conn.user, port=conn.port, dry_run_first=True)
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

        # 2. Reboot into the upgraded system. A dropped SSH session during reboot
        #    is expected and counts as success — the workflow confirms via reconnect.
        try:
            rb = executor.run_template(conn.host, "os.reboot", {}, key=key,
                                       user=conn.user, port=conn.port, dry_run_first=False)
            reboot_issued = (not rb.applied) or (rb.result is None) or (rb.result.exit_code == 0)
        except Exception:  # noqa: BLE001 - reboot severs the connection; that's success
            reboot_issued = True

        return ToolResult(
            ok=True, tool=OS_UPGRADE_TOOL,
            summary=(f"release upgrade applied on {asset_id}; reboot issued"
                     + (f" (target {target})" if target else "")),
            data={"asset_id": asset_id, "target_version": target,
                  "upgrade_exit": res.exit_code, "reboot_issued": reboot_issued,
                  "rollback": rb_json},
            resolved_command=up.resolved_command)

    return ToolSpec(
        name=OS_UPGRADE_TOOL,
        schema={
            "type": "object",
            "required": ["asset_id"],
            "properties": {
                "asset_id": {"type": "string"},
                "target_version": {"type": "string"},
                "snapshot_id": {"type": "string"},
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
    )
