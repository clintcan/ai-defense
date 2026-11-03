"""Real SSH transport backed by paramiko (optional ``ssh`` extra).

Implements the ``Transport`` protocol used by SSHExecutor. The private key is
passed in by the caller (resolved from the vault at call time) and used only to
connect; it never appears in the argv or any returned/logged value.

Host-key verification is ON by default (known_hosts); set ``allow_unknown_hosts``
to accept unknown hosts (trust-on-first-use) only when you understand the risk.
"""

from __future__ import annotations

import io
import os
import shlex
import shutil
import subprocess
import tempfile

from .executor import CommandOutput

_PPK_HEADER = "PuTTY-User-Key-File"
_PPK_HELP = (
    "encrypted PuTTY .ppk: native parsing supports only unencrypted keys, and "
    "'puttygen' is not on PATH to convert this one. Either install a CLI puttygen "
    "(Linux/WSL), or export an OpenSSH key once from the PuTTYgen GUI "
    "(Conversions -> Export OpenSSH key)."
)


def _convert_ppk(key_text: str, passphrase: str | None) -> str:
    """Convert a PuTTY .ppk to an OpenSSH private key using puttygen on PATH.

    puttygen needs file paths, so the key is written to a private temp file,
    converted, read back, and both temp files are removed immediately."""
    puttygen = shutil.which("puttygen")
    if not puttygen:
        raise ValueError(_PPK_HELP)

    in_fd, in_path = tempfile.mkstemp(suffix=".ppk")
    out_path = in_path + ".openssh"
    pass_path = None
    try:
        with os.fdopen(in_fd, "w") as f:
            f.write(key_text)
        try:
            os.chmod(in_path, 0o600)
        except OSError:
            pass
        cmd = [puttygen, in_path, "-O", "private-openssh", "-o", out_path]
        if passphrase:
            pass_fd, pass_path = tempfile.mkstemp()
            with os.fdopen(pass_fd, "w") as pf:
                pf.write(passphrase)
            cmd += ["--old-passphrase", pass_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0 or not os.path.exists(out_path):
            raise ValueError(f"puttygen conversion failed: {proc.stderr.strip()}")
        with open(out_path) as f:
            return f.read()
    finally:
        for p in (in_path, out_path, pass_path):
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


def _load_key(key_text: str, passphrase: str | None):
    import paramiko

    # PuTTY .ppk is not an OpenSSH key. Parse it natively (pure Python, no tools)
    # for unencrypted keys; for an encrypted .ppk fall back to puttygen if present.
    if key_text.lstrip().startswith(_PPK_HEADER):
        from .ppk import PpkEncryptedError, ppk_to_openssh_pem
        try:
            key_text = ppk_to_openssh_pem(key_text)
            passphrase = None
        except PpkEncryptedError:
            key_text = _convert_ppk(key_text, passphrase)   # needs puttygen CLI
            passphrase = None

    # Try the common key types; paramiko has no single auto-detect loader.
    for cls in (getattr(paramiko, n) for n in
                ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey") if hasattr(paramiko, n)):
        try:
            return cls.from_private_key(io.StringIO(key_text), password=passphrase)
        except paramiko.SSHException:
            continue
    raise ValueError("unsupported or unparseable SSH private key (expected an "
                     "OpenSSH/PEM private key)")


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
