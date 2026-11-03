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
_OS_RELEASE = ["cat", "/etc/os-release"]

# Read-only upgrade-eligibility probes (Debian/Ubuntu). None mutate anything.
_REBOOT_REQUIRED = ["test", "-f", "/var/run/reboot-required"]   # exit 0 => pending
_DISK_FREE = ["df", "-Pk", "/"]                                 # POSIX 1K blocks
_HELD_PACKAGES = ["apt-mark", "showhold"]
_BROKEN_PACKAGES = ["dpkg", "--audit"]

# Ubuntu .04 releases are LTS (OSV tags them "Ubuntu:<ver>:LTS").
_UBUNTU_LTS = {"18.04", "20.04", "22.04", "24.04", "16.04", "14.04"}


def parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip('"')
    return data


def osv_ecosystem(os_release: dict[str, str]) -> str | None:
    """Map /etc/os-release to the OSV distro ecosystem (e.g. 'Ubuntu:18.04:LTS',
    'Debian:10'). Returns None for anything unrecognized, so callers fall back to
    a configured default."""
    osid = (os_release.get("ID") or "").lower()
    ver = os_release.get("VERSION_ID") or ""
    if osid == "ubuntu" and ver:
        return f"Ubuntu:{ver}:LTS" if ver in _UBUNTU_LTS else f"Ubuntu:{ver}"
    if osid == "debian" and ver:
        return f"Debian:{ver}"
    if osid in ("alpine",) and ver:
        return f"Alpine:v{'.'.join(ver.split('.')[:2])}"
    return None


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

        def run(argv):
            return self._transport.run(conn.host, argv, key=key, timeout=60,
                                       user=conn.user, port=conn.port)

        # OS detection (read-only) -> per-host OSV ecosystem + raw os-release.
        osr = run(_OS_RELEASE)
        os_release = parse_os_release(osr.stdout) if osr.exit_code == 0 else {}
        ecosystem = osv_ecosystem(os_release) if os_release else None

        out = run(_DPKG_QUERY)
        ok = out.exit_code == 0
        return {
            "installed_packages": _parse_dpkg(out.stdout) if ok else {},
            "ecosystem": ecosystem,
            "os_release": os_release,
            "applied_patches": [],
            "misconfigurations": [] if ok else [f"scan failed: exit {out.exit_code}"],
        }

    def collect_upgrade_state(self, asset_id: str) -> dict:
        """Read-only probes that decide OS-upgrade eligibility. Each probe is
        independently resilient: a failing probe yields an unknown value rather
        than failing the whole preflight. Strictly non-mutating."""
        conn = self._resolve_conn(asset_id)
        key = self._vault.resolve(conn.key_ref, actor=self._actor,
                                  reason=f"upgrade-preflight {asset_id}")

        def run(argv):
            return self._transport.run(conn.host, argv, key=key, timeout=30,
                                       user=conn.user, port=conn.port)

        reboot = run(_REBOOT_REQUIRED)
        df = run(_DISK_FREE)
        held = run(_HELD_PACKAGES)
        broken = run(_BROKEN_PACKAGES)
        return {
            "reboot_required": reboot.exit_code == 0,
            "disk_free_mb": _parse_df_free_mb(df.stdout) if df.exit_code == 0 else None,
            "held_packages": ([ln.strip() for ln in held.stdout.splitlines() if ln.strip()]
                              if held.exit_code == 0 else []),
            "broken_packages_report": broken.stdout.strip() if broken.exit_code == 0 else "",
        }


def _parse_dpkg(text: str) -> dict[str, str]:
    packages: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0]:
            packages[parts[0]] = parts[1].strip()
    return packages


def _parse_df_free_mb(text: str) -> int | None:
    """Available MB on / from ``df -Pk /`` output (POSIX 1K-block format).

    The data row's 4th column is 1K-blocks available. POSIX guarantees a single
    logical data line even when the device name wraps, but we scan for the first
    line with enough numeric columns to be safe."""
    for line in text.splitlines()[1:]:          # skip the header row
        parts = line.split()
        if len(parts) >= 4:
            try:
                return int(parts[3]) // 1024
            except ValueError:
                continue
    return None
