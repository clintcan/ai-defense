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
from datetime import UTC, datetime

from ..registry.assets import AssetRegistry, ConnectionInfo
from ..toolset.intents import ToolResult
from ..toolset.registry import ToolCapability, ToolSpec
from .executor import SSHExecutor
from .hardening import PrimitiveKind, RollbackAction

SECURITY_UPDATE_TOOL = "patch.apply_security_update"

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
