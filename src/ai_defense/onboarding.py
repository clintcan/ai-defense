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
ASSET_UPDATE_TOOL = "asset.update_connection"
CLOUD_ACCOUNT_REGISTER_TOOL = "cloud.register_account"


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


def update_ssh_connection(repo, asset_id: str, *, host: str | None = None,
                          port: int | None = None, user: str | None = None,
                          key_ref: str | None = None) -> Asset:
    """Option 1 (operator, out-of-band): correct an already-registered ssh-host's
    connection fields — e.g. a rotated ``key_ref`` or a changed address — WITHOUT
    re-onboarding. The authorization/attestation is preserved; only the connection
    changes. ``repo`` exposes ``update_connection`` (AssetRepository or a registry).

    Like ``register-vps``, the key must already be in the vault under ``key_ref``;
    this stores only the reference, never the key."""
    return repo.update_connection(asset_id, host=host, port=port, user=user,
                                  key_ref=key_ref)


# SSH login user by cloud image family (substring match on the platform /
# Lightsail blueprint id). Covers the common AWS images; override with --user.
# OS-only blueprints use their distro user; Lightsail application stacks are
# Bitnami images and log in as `bitnami`.
_USER_BY_PLATFORM: list[tuple[str, str]] = [
    ("ubuntu", "ubuntu"),
    ("debian", "admin"),
    ("amazon", "ec2-user"),
    ("amzn", "ec2-user"),
    ("rhel", "ec2-user"),
    ("centos", "centos"),
    ("fedora", "fedora"),
    ("suse", "ec2-user"),
    # Lightsail Bitnami application stacks -> `bitnami`
    ("bitnami", "bitnami"),
    ("wordpress", "bitnami"),
    ("lamp", "bitnami"),
    ("lemp", "bitnami"),
    ("mean", "bitnami"),
    ("node", "bitnami"),        # nodejs_*
    ("django", "bitnami"),
    ("ghost", "bitnami"),
    ("drupal", "bitnami"),
    ("joomla", "bitnami"),
    ("magento", "bitnami"),
    ("redmine", "bitnami"),
    ("gitlab", "bitnami"),
    ("prestashop", "bitnami"),
    ("opencart", "bitnami"),
    ("mediawiki", "bitnami"),
    ("phpbb", "bitnami"),
    ("nginx", "bitnami"),
    ("plesk", "ubuntu"),
]


def infer_ssh_user(platform: str | None, default: str = "ubuntu") -> str:
    """Best-effort SSH user for a discovered instance's platform/blueprint.

    It's only a guess (the operator can override with ``user=``); getting it
    wrong fails the scan loudly rather than doing anything unsafe."""
    p = (platform or "").lower()
    for key, user in _USER_BY_PLATFORM:
        if key in p:
            return user
    return default


def onboard_instances(
    instances: list[dict], register: Callable[[Asset], None], *,
    owner: str, granted_by: str, attestation_sig: str,
    environment: str | None = None,
    default_key_ref: str | None = None, key_ref_by_name: dict[str, str] | None = None,
    user: str | None = None, port: int = 22, ttl_days: int = 90,
    existing_ids: set[str] | None = None, update: bool = False,
    now: datetime | None = None, dry_run: bool = False,
) -> dict:
    """Operator bulk onboarding (option 1, out-of-band) from discovered cloud
    instances (the normalized dicts ``cloud_discover`` returns).

    One signed ssh-host registration per instance. A host is **skipped** (never
    guessed around) when it is already registered (unless ``update``), is not
    running, lacks a reachable address, or lacks a ``key_ref`` — the SSH private
    key must already be in the vault; only the reference is stored, never the
    key. ``dry_run`` builds and reports the registrations without writing.
    Returns ``{registered: [...], skipped: [{instance, reason}], dry_run}``."""
    now = now or _utcnow()
    key_map = key_ref_by_name or {}
    known = existing_ids or set()
    registered: list[dict] = []
    skipped: list[dict] = []

    for inst in instances:
        name = inst.get("name") or inst.get("instance_id")
        if not name:
            skipped.append({"instance": "<unnamed>", "reason": "no name/instance_id"})
            continue
        if name in known and not update:
            skipped.append({"instance": name,
                            "reason": "already registered (use --update to overwrite)"})
            continue
        state = inst.get("state")
        if state is not None and state != "running":
            skipped.append({"instance": name, "reason": f"not running (state={state})"})
            continue
        host = inst.get("public_ip") or inst.get("private_ip")
        if not host:
            skipped.append({"instance": name, "reason": "no public_ip or private_ip"})
            continue
        key_ref = key_map.get(name, default_key_ref)
        if not key_ref:
            skipped.append({"instance": name,
                            "reason": "no key_ref (pass --key-ref or a --key-ref-map entry)"})
            continue

        env = environment or (inst.get("tags") or {}).get("env") or "unknown"
        ssh_user = user or infer_ssh_user(inst.get("platform"))
        asset = build_ssh_asset(
            asset_id=name, host=host, key_ref=key_ref, owner=owner, environment=env,
            granted_by=granted_by, attestation_sig=attestation_sig,
            user=ssh_user, port=port, ttl_days=ttl_days, now=now,
        )
        if not dry_run:
            register(asset)
        registered.append({"asset_id": name, "host": host, "user": ssh_user,
                           "environment": env, "key_ref": key_ref,
                           "service": inst.get("service")})
    return {"registered": registered, "skipped": skipped, "dry_run": dry_run}


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


def make_asset_update_tool(update_fn: Callable[..., Asset]) -> ToolSpec:
    """Option 2: an LLM-proposable, approval-gated tool to correct an existing
    ssh-host's connection fields (``host``/``port``/``user``/``key_ref``) without
    re-onboarding — the fix for a rotated key or a rebuilt host that changed IP.

    ``update_fn`` is a registry's ``update_connection`` (in-memory or DB-backed);
    it preserves the asset's authorization. The intent targets the asset itself,
    so the dispatcher's authorization check enforces that only an already-
    registered, authorized asset can be updated. Dispatched under the ONBOARD
    action class (approval-gated), capability MUTATING. Only a ``key_ref`` that
    resolves in the vault is accepted — the key value is never handled here."""

    _FIELDS = ("host", "port", "user", "key_ref")

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        changes = {k: params[k] for k in _FIELDS
                   if k in params and params[k] is not None}
        if not changes:
            return ToolResult(ok=False, tool=ASSET_UPDATE_TOOL,
                              summary="no connection fields to update "
                                      "(provide host, port, user, and/or key_ref)")
        if "key_ref" in changes and not resolve_secret(changes["key_ref"]):
            return ToolResult(ok=False, tool=ASSET_UPDATE_TOOL,
                              summary=f"key_ref not found in vault: {changes['key_ref']}",
                              data={"key_ref": changes["key_ref"]})
        try:
            asset = update_fn(params["asset_id"], **changes)
        except (KeyError, ValueError) as exc:
            return ToolResult(ok=False, tool=ASSET_UPDATE_TOOL, summary=str(exc))
        conn = asset.connection
        return ToolResult(
            ok=True, tool=ASSET_UPDATE_TOOL,
            summary=f"updated connection for {asset.asset_id} "
                    f"({conn.user}@{conn.host}:{conn.port})",
            data={"asset_id": asset.asset_id, "host": conn.host, "port": conn.port,
                  "user": conn.user, "key_ref": conn.key_ref,
                  "changed": sorted(changes)},
        )

    return ToolSpec(
        name=ASSET_UPDATE_TOOL,
        schema={
            "type": "object",
            "required": ["asset_id"],
            "properties": {
                "asset_id": {"type": "string"},
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "user": {"type": "string"},
                "key_ref": {"type": "string"},    # vault ref only; never the key
            },
        },
        executor=_execute,
        capability=ToolCapability.MUTATING,
    )


def build_cloud_asset(
    *, account_id: str, provider: str, credential_ref: str, owner: str,
    environment: str, granted_by: str, attestation_sig: str,
    ttl_days: int = 365, now: datetime | None = None,
) -> Asset:
    now = now or _utcnow()
    return Asset(
        asset_id=account_id, kind=f"cloud-account:{provider}", owner=owner,
        environment=environment,
        authorization=Authorization(
            attestation_sig=attestation_sig, granted_by=granted_by,
            granted_at=now, expires_at=now + timedelta(days=ttl_days),
        ),
        attributes={"credential_ref": credential_ref, "provider": provider},
    )


def make_cloud_account_register_tool(register_fn: Callable[[Asset], None]) -> ToolSpec:
    """LLM-proposable, approval-gated onboarding of a cloud account (ONBOARD).

    The account's AWS credential must already be in the vault, referenced by
    ``credential_ref`` (the tool verifies it resolves, never handling the value).
    Like SSH onboarding, the intent must target a registered control-plane asset."""

    def _execute(params: dict, *, resolve_secret) -> ToolResult:
        credential_ref = params["credential_ref"]
        if not resolve_secret(credential_ref):
            return ToolResult(ok=False, tool=CLOUD_ACCOUNT_REGISTER_TOOL,
                              summary=f"credential_ref not found in vault: {credential_ref}",
                              data={"credential_ref": credential_ref})
        asset = build_cloud_asset(
            account_id=params["account_id"], provider=params.get("provider", "aws"),
            credential_ref=credential_ref, owner=params["owner"],
            environment=params["environment"], granted_by=params["granted_by"],
            attestation_sig=f"approved-by:{params['granted_by']}",
            ttl_days=params.get("ttl_days", 365),
        )
        register_fn(asset)
        return ToolResult(
            ok=True, tool=CLOUD_ACCOUNT_REGISTER_TOOL,
            summary=f"registered {asset.kind} {asset.asset_id}",
            data={"account_id": asset.asset_id, "provider": asset.attributes["provider"],
                  "environment": asset.environment, "credential_ref": credential_ref},
        )

    return ToolSpec(
        name=CLOUD_ACCOUNT_REGISTER_TOOL,
        schema={
            "type": "object",
            "required": ["account_id", "credential_ref", "owner", "environment",
                         "granted_by"],
            "properties": {
                "account_id": {"type": "string"},
                "provider": {"type": "string"},
                "credential_ref": {"type": "string"},
                "owner": {"type": "string"},
                "environment": {"type": "string"},
                "granted_by": {"type": "string"},
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
