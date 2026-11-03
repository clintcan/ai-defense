"""Asset onboarding — register a new managed asset (e.g. a VPS for SSH).

Registering an asset is the trust root of the system, so it is always a
human-anchored act. Two paths, both ending in the same signed registration:

  * Option 1 (operator, out-of-band): ``register_ssh_host`` / the ``register-vps``
    CLI. A person runs it; they supply the attestation.
  * Option 2 (LLM-proposed, approval-gated): ``make_asset_register_tool`` — the
    model drafts the (non-secret) details as an ONBOARD intent that must target a
    pre-registered control-plane asset and pass through the approval gate before
    anything is written. The SSH private key is never in the intent; only a
    ``key_ref`` the operator pre-loaded into the vault, which the tool verifies
    resolves.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from .registry.assets import Asset, Authorization, ConnectionInfo
from .toolset.intents import ToolResult
from .toolset.registry import ToolCapability, ToolSpec

ASSET_REGISTER_TOOL = "asset.register"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def build_ssh_asset(
    *, asset_id: str, host: str, key_ref: str, owner: str, environment: str,
    granted_by: str, attestation_sig: str, user: str = "root", port: int = 22,
    ttl_days: int = 90, now: datetime | None = None,
) -> Asset:
    now = now or _utcnow()
    return Asset(
        asset_id=asset_id, kind="ssh-host", owner=owner, environment=environment,
        authorization=Authorization(
            attestation_sig=attestation_sig, granted_by=granted_by,
            granted_at=now, expires_at=now + timedelta(days=ttl_days),
        ),
        connection=ConnectionInfo(host=host, key_ref=key_ref, port=port, user=user),
    )


def register_ssh_host(repo, **kwargs) -> Asset:
    """Option 1: operator registers a VPS directly (out-of-band). ``repo`` is an
    AssetRepository; ``kwargs`` are ``build_ssh_asset`` arguments."""
    asset = build_ssh_asset(**kwargs)
    repo.save(asset)
    return asset


def make_asset_register_tool(register_fn: Callable[[Asset], None]) -> ToolSpec:
    """Option 2: an LLM-proposable, approval-gated onboarding tool.

    ``register_fn`` persists the Asset (e.g. ``AssetRepository.save`` or
    ``AssetRegistry.register``). The intent must target a registered
    control-plane asset (enforced by the dispatcher's authorization check) and is
    dispatched under the ONBOARD action class (approval-gated by policy)."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        key_ref = params["key_ref"]
        # Confirm the operator pre-loaded the key into the vault; never handle
        # the value (dispatcher redaction scrubs it regardless).
        if not resolve_secret(key_ref):
            return ToolResult(ok=False, tool=ASSET_REGISTER_TOOL,
                              summary=f"key_ref not found in vault: {key_ref}",
                              data={"key_ref": key_ref})
        asset = build_ssh_asset(
            asset_id=params["asset_id"], host=params["host"], key_ref=key_ref,
            owner=params["owner"], environment=params["environment"],
            granted_by=params["granted_by"],
            # Links the authorization to the approving human; a production system
            # binds the approver's cryptographic signature here.
            attestation_sig=f"approved-by:{params['granted_by']}",
            user=params.get("user", "root"), port=params.get("port", 22),
            ttl_days=params.get("ttl_days", 90),
        )
        register_fn(asset)
        return ToolResult(
            ok=True, tool=ASSET_REGISTER_TOOL,
            summary=f"registered ssh-host {asset.asset_id} ({asset.connection.host})",
            data={"asset_id": asset.asset_id, "host": asset.connection.host,
                  "environment": asset.environment, "key_ref": key_ref,
                  "expires_at": asset.authorization.expires_at.isoformat()},
        )

    return ToolSpec(
        name=ASSET_REGISTER_TOOL,
        schema={
            "type": "object",
            "required": ["asset_id", "host", "key_ref", "owner", "environment",
                         "granted_by"],
            "properties": {
                "asset_id": {"type": "string"},
                "host": {"type": "string"},
                "key_ref": {"type": "string"},    # vault ref only; never the key
                "owner": {"type": "string"},
                "environment": {"type": "string"},
                "granted_by": {"type": "string"},
                "user": {"type": "string"},
                "port": {"type": "integer"},
                "ttl_days": {"type": "integer"},
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
    )


def main(argv: list[str] | None = None) -> int:
    """`register-vps` operator CLI (option 1). Writes the asset to a SQLite DB;
    the SSH key must already be stored in the vault under --key-ref."""
    import argparse

    from .db import AssetRepository, init_db

    p = argparse.ArgumentParser(prog="register-vps", description=__doc__)
    p.add_argument("--db", required=True, help="SQLite path, e.g. sqlite+pysqlite:///ai.db")
    p.add_argument("--asset-id", required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--key-ref", required=True, help="vault reference (key already stored)")
    p.add_argument("--owner", required=True)
    p.add_argument("--environment", required=True)
    p.add_argument("--granted-by", required=True)
    p.add_argument("--attestation-sig", required=True)
    p.add_argument("--user", default="root")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--ttl-days", type=int, default=90)
    args = p.parse_args(argv)

    repo = AssetRepository(init_db(args.db))
    asset = register_ssh_host(
        repo, asset_id=args.asset_id, host=args.host, key_ref=args.key_ref,
        owner=args.owner, environment=args.environment, granted_by=args.granted_by,
        attestation_sig=args.attestation_sig, user=args.user, port=args.port,
        ttl_days=args.ttl_days,
    )
    print(f"registered {asset.asset_id} -> {asset.connection.host} "
          f"(expires {asset.authorization.expires_at.isoformat()})")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
