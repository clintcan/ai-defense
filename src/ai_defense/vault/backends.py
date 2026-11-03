"""Concrete secrets backends.

These resolve a ``key_ref`` to secret material kept OUTSIDE the database (a
protected key directory or an environment variable), matching the design: the DB
only ever holds references, never the key. For a production deployment prefer a
real secrets manager (HashiCorp Vault / AWS Secrets Manager) behind the same
``SecretsBackend`` interface; these cover the common operator-managed cases.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .vault import SecretsBackend

# A ref is a safe relative name like "ssh-key/vps-demo-01". Reject anything that
# could escape the key directory or hit an unexpected env var.
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


def _validate(ref: str) -> None:
    if not _SAFE_REF.match(ref) or ".." in ref.split("/"):
        raise KeyError(f"invalid secret ref: {ref!r}")


class FileVaultBackend(SecretsBackend):
    """Resolve ``key_ref`` to the contents of ``<root>/<ref>`` (e.g. an SSH
    private key file). The key directory should be owner-only (chmod 700) and
    kept out of version control."""

    def __init__(self, root: str | os.PathLike) -> None:
        self._root = Path(root).resolve()

    def resolve(self, ref: str):
        _validate(ref)
        path = (self._root / ref).resolve()
        # defence in depth: the resolved path must stay under the key root
        if not str(path).startswith(str(self._root)):
            raise KeyError(f"secret ref escapes key root: {ref!r}")
        if not path.is_file():
            raise KeyError(f"secret not found: {ref}")
        return path.read_text()

    def audit_access(self, ref: str, *, actor: str, reason: str) -> None:
        # The value is never logged; a real backend would emit an audit event.
        pass


class EnvVaultBackend(SecretsBackend):
    """Resolve ``key_ref`` from an environment variable. ``ssh-key/vps-demo-01``
    with prefix ``AID_SECRET_`` looks up ``AID_SECRET_SSH_KEY_VPS_DEMO_01``."""

    def __init__(self, prefix: str = "AID_SECRET_") -> None:
        self._prefix = prefix

    def _env_name(self, ref: str) -> str:
        _validate(ref)
        return self._prefix + re.sub(r"[^A-Za-z0-9]", "_", ref).upper()

    def resolve(self, ref: str):
        name = self._env_name(ref)
        value = os.environ.get(name)
        if value is None:
            raise KeyError(f"secret not found in env: {name}")
        return value

    def audit_access(self, ref: str, *, actor: str, reason: str) -> None:
        pass
