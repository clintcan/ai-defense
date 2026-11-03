"""SSH command executor on a pluggable transport.

Flow for one command: render from the allowlist catalog -> denylist check ->
(optional) dry-run -> apply -> capture output. The executor never builds a
command from free-form text and never holds a shell. The private key/cert is
passed in by the caller (resolved from the vault by the toolset at dispatch
time) and handed to the transport to establish the connection; it is never part
of the argv or the returned ``resolved_command``.

The transport is injected so the executor is testable without real hosts. The
production transport is a non-interactive SSH client (e.g. Paramiko) with no
TTY; a fake transport is used in tests.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Protocol

from .catalog import CATALOG, CommandTemplate
from .denylist import is_denied

DEFAULT_TIMEOUT_S = 60
MAX_OUTPUT_BYTES = 64 * 1024


@dataclass(frozen=True)
class CommandOutput:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


class Transport(Protocol):
    """Executes an argv on a host over SSH. MUST use ``key`` only to connect,
    never log it, and run non-interactively (no TTY)."""

    def run(self, host: str, argv: list[str], *, key: str, timeout: int) -> CommandOutput: ...


@dataclass(frozen=True)
class ExecOutcome:
    applied: bool                       # True iff the real (non-dry-run) command ran
    resolved_command: str               # display form of the applied argv (no secrets)
    dry_run: CommandOutput | None = None
    result: CommandOutput | None = None
    blocked_reason: str | None = None   # set when refused before applying


class SSHExecutor:
    def __init__(self, transport: Transport, *,
                 timeout_s: int = DEFAULT_TIMEOUT_S,
                 max_output_bytes: int = MAX_OUTPUT_BYTES) -> None:
        self._transport = transport
        self._timeout_s = timeout_s
        self._max_output = max_output_bytes

    def run_template(self, host: str, template_name: str, params: dict, *,
                     key: str, dry_run_first: bool = True) -> ExecOutcome:
        template: CommandTemplate = CATALOG[template_name]   # KeyError if not allowlisted
        argv = template.render(params)
        cmd = shlex.join(argv)

        # Denylist wins even over anything the catalog produced.
        if is_denied(cmd):
            return ExecOutcome(applied=False, resolved_command=cmd,
                               blocked_reason="denylist: destructive pattern")

        # Dry-run first where the tool supports it; abort apply if it fails.
        dry: CommandOutput | None = None
        if dry_run_first:
            dargv = template.render_dry_run(params)
            if dargv is not None:
                if is_denied(shlex.join(dargv)):
                    return ExecOutcome(applied=False, resolved_command=cmd,
                                       blocked_reason="denylist: destructive pattern (dry-run)")
                dry = self._cap(self._transport.run(host, dargv, key=key, timeout=self._timeout_s))
                if dry.exit_code != 0:
                    return ExecOutcome(applied=False, resolved_command=cmd, dry_run=dry,
                                       blocked_reason=f"dry-run failed (exit {dry.exit_code})")

        result = self._cap(self._transport.run(host, argv, key=key, timeout=self._timeout_s))
        return ExecOutcome(applied=True, resolved_command=cmd, dry_run=dry, result=result)

    def _cap(self, out: CommandOutput) -> CommandOutput:
        if len(out.stdout) <= self._max_output and len(out.stderr) <= self._max_output:
            return out
        return CommandOutput(
            exit_code=out.exit_code,
            stdout=self._truncate(out.stdout),
            stderr=self._truncate(out.stderr),
        )

    def _truncate(self, text: str) -> str:
        if len(text) <= self._max_output:
            return text
        return text[: self._max_output] + "...[truncated]"
