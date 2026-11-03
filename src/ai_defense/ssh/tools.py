"""SSH-backed tools, registered into the toolset as dispatchable Executors.

A factory binds an ``SSHExecutor`` to a catalog template and returns an Executor
closure matching the toolset protocol ``(params, *, resolve_secret) -> ToolResult``.
The closure resolves the SSH key via the injected ``resolve_secret`` callback
(so the key is fetched from the vault at call time and never held elsewhere),
runs the template (dry-run first), and reports a result that carries a recorded
rollback action.
"""

from __future__ import annotations

from ..toolset.intents import ToolResult
from ..toolset.registry import ToolCapability, ToolSpec
from .executor import SSHExecutor
from .hardening import PrimitiveKind, RollbackAction

SECURITY_UPDATE_TOOL = "patch.apply_security_update"


def make_security_update_tool(
    executor: SSHExecutor, template_name: str = "apt.install_security",
) -> ToolSpec:
    """Build the ``patch.apply_security_update`` tool (capability=MUTATING).

    Params: ``host`` (asset id / connection target), ``package`` (the package to
    upgrade), ``key_ref`` (vault reference for the SSH key), and optional
    ``snapshot_id`` (the protective snapshot taken before the change, used for
    rollback).
    """

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        host = params["host"]
        package = params["package"]
        key = resolve_secret(params["key_ref"])

        outcome = executor.run_template(
            host, template_name, {"package": package}, key=key, dry_run_first=True,
        )

        rollback = RollbackAction(
            kind=PrimitiveKind.PACKAGE,
            description=(
                f"restore '{package}' on {host}: reinstall the prior version, "
                f"or restore pre-change snapshot {params.get('snapshot_id', '<none>')}"
            ),
            payload={"host": host, "package": package,
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
        summary = (f"{package} upgraded on {host}" if ok
                   else f"{package} upgrade failed on {host} (exit {exit_str})")
        return ToolResult(
            ok=ok, tool=SECURITY_UPDATE_TOOL,
            summary=summary,
            data={
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
            "required": ["host", "package", "key_ref"],
            "properties": {
                "host": {"type": "string"},
                "package": {"type": "string"},
                "key_ref": {"type": "string"},
                "snapshot_id": {"type": "string"},
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
    )
