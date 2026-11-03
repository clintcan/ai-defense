"""Real SSH transport backed by paramiko (optional ``ssh`` extra).

Implements the ``Transport`` protocol used by SSHExecutor. The private key is
passed in by the caller (resolved from the vault at call time) and used only to
connect; it never appears in the argv or any returned/logged value.

Host-key verification is ON by default (known_hosts); set ``allow_unknown_hosts``
to accept unknown hosts (trust-on-first-use) only when you understand the risk.
"""

from __future__ import annotations

import io
import shlex

from .executor import CommandOutput


def _load_key(key_text: str, passphrase: str | None):
    import paramiko
    # Try the common key types; paramiko has no single auto-detect loader.
    for cls in (getattr(paramiko, n) for n in
                ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey") if hasattr(paramiko, n)):
        try:
            return cls.from_private_key(io.StringIO(key_text), password=passphrase)
        except paramiko.SSHException:
            continue
    raise ValueError("unsupported or unparseable SSH private key")


class ParamikoTransport:
    """A non-interactive SSH transport. One connection per command (simple and
    safe); a pooling version can come later if throughput matters."""

    def __init__(self, *, known_hosts: str | None = None,
                 allow_unknown_hosts: bool = False,
                 connect_timeout: int = 15,
                 key_passphrase: str | None = None) -> None:
        self._known_hosts = known_hosts
        self._allow_unknown = allow_unknown_hosts
        self._connect_timeout = connect_timeout
        self._passphrase = key_passphrase

    def run(self, host: str, argv: list[str], *, key: str, timeout: int,
            user: str = "root", port: int = 22) -> CommandOutput:
        import paramiko

        client = paramiko.SSHClient()
        if self._known_hosts:
            client.load_host_keys(self._known_hosts)
        else:
            client.load_system_host_keys()
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if self._allow_unknown else paramiko.RejectPolicy())

        pkey = _load_key(key, self._passphrase)
        try:
            client.connect(
                hostname=host, port=port, username=user, pkey=pkey,
                timeout=self._connect_timeout, allow_agent=False, look_for_keys=False,
            )
            # Build a single command string from argv with proper shell quoting;
            # argv came from the allowlist catalog, never free-form planner text.
            command = " ".join(shlex.quote(a) for a in argv)
            _stdin, stdout, stderr = client.exec_command(
                command, timeout=timeout, get_pty=False)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
            return CommandOutput(exit_code=code, stdout=out, stderr=err)
        finally:
            client.close()
