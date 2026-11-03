"""Read-only SSH host inspector (real counterpart to the demo inspector).

Resolves an asset's connection from the registry and its key from the vault,
then runs a fixed, read-only query command over the transport to collect the
installed package inventory. Detection only — it runs no mutating command and
has no dry-run/write path (CLAUDE.md component 5).
"""

from __future__ import annotations

from .scanner import HostInspector  # noqa: F401 (documents the protocol it satisfies)

# Debian/Ubuntu package inventory, one "name version" per line. Read-only.
_DPKG_QUERY = ["dpkg-query", "-W", "-f=${Package} ${Version}\n"]


class SSHHostInspector:
    """``collect(asset_id)`` -> observed state dict for the scanner.

    ``connection_resolver`` maps asset_id -> ConnectionInfo (host/user/port/
    key_ref), ``vault`` resolves the key_ref, and ``transport`` runs the query.
    """

    def __init__(self, connection_resolver, vault, transport, *, actor: str = "scanner") -> None:
        self._resolve_conn = connection_resolver
        self._vault = vault
        self._transport = transport
        self._actor = actor

    def collect(self, asset_id: str) -> dict:
        conn = self._resolve_conn(asset_id)
        key = self._vault.resolve(conn.key_ref, actor=self._actor,
                                  reason=f"scan {asset_id}")
        out = self._transport.run(conn.host, _DPKG_QUERY, key=key, timeout=60,
                                  user=conn.user, port=conn.port)
        ok = out.exit_code == 0
        return {
            "installed_packages": _parse_dpkg(out.stdout) if ok else {},
            "applied_patches": [],
            "misconfigurations": [] if ok else [f"scan failed: exit {out.exit_code}"],
        }


def _parse_dpkg(text: str) -> dict[str, str]:
    packages: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0]:
            packages[parts[0]] = parts[1].strip()
    return packages
