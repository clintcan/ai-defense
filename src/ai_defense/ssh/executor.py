"""SSH command executor. Resolves template -> dry-run -> approval -> execute."""

from __future__ import annotations

from ..toolset.intents import ToolResult


class SSHExecutor:
    """TODO: implement with a non-interactive SSH client (e.g. paramiko).

    Hard requirements:
      * key/cert fetched from vault at call time, never held by the planner
      * command built only from ssh.catalog templates
      * ssh.denylist check before anything runs
      * dry-run first where supported; show resolved command to approver
      * no TTY; enforce timeout, output size cap, per-host concurrency cap
      * capture stdout/stderr/exit code to the audit log (secrets redacted)
    """

    def run(self, template_name: str, params: dict, *, approved_by: str | None) -> ToolResult:
        raise NotImplementedError
