"""`python -m ai_defense` — operator entrypoint.

Subcommands:
  demo          Run the full lifecycle locally against the demo backends (no infra).
  mcp           Run the MCP server over stdio.
  report        Scan asset(s) and write vulnerability reports to local files.
  bulk-onboard  Register discovered cloud instances as ssh-host assets (operator).
  update-asset  Correct an ssh-host's connection info (operator; preserves attestation).
  pending       List approval change-sets in a DB.
  approve       Approve a pending change-set.
"""

from __future__ import annotations

import argparse


def _add_engine_args(p: argparse.ArgumentParser) -> None:
    """Flags shared by every command that builds a live engine (mcp, report)."""
    p.add_argument("--db", default=None,
                   help="DB URL for a durable engine shared with the operator CLI")
    p.add_argument("--ssh-keys", default=None,
                   help="key directory -> use the real SSH backend (needs 'ssh' extra)")
    p.add_argument("--known-hosts", default=None, help="known_hosts file for host-key checks")
    p.add_argument("--allow-unknown-hosts", action="store_true",
                   help="accept unknown SSH host keys (trust on first use; less safe)")
    p.add_argument("--aws-region", default=None,
                   help="default AWS region -> use live boto3 for cloud tools "
                        "(needs 'aws' extra; creds resolved from the vault)")
    p.add_argument("--osv", action="store_true",
                   help="pull real advisories from OSV.dev for observed packages")
    p.add_argument("--osv-ecosystem", default="Debian",
                   help="OSV ecosystem for queries (default: Debian; auto-detected per host)")
    p.add_argument("--kev", action="store_true",
                   help="mark CISA KEV (known-exploited) advisories -> top priority")


def _engine_from_args(args):
    from .mcp_server import _engine_for
    return _engine_for(None, args.db, ssh_keys=args.ssh_keys, known_hosts=args.known_hosts,
                       allow_unknown_hosts=args.allow_unknown_hosts, aws_region=args.aws_region,
                       osv=args.osv, osv_ecosystem=args.osv_ecosystem, kev=args.kev)


def _fleet_asset_ids(engine) -> list[str]:
    """Registered hosts we can authenticate to and scan (ssh-host assets with a
    connection). Cloud-account and control-plane assets are not SSH-scannable."""
    return [a.asset_id for a in engine.list_assets()
            if getattr(a, "connection", None) is not None and a.kind == "ssh-host"]


def _run_demo() -> int:
    from .demo import scripted_demo

    print("AI Defense - demo run (simulated backends; nothing leaves this process)\n")
    for i, step in enumerate(scripted_demo(), 1):
        print(f"{i}. {step.title}")
        for line in step.detail.splitlines():
            print(f"     {line}" if not line.startswith("  ") else f"   {line}")
        print()
    print("Done. Every action above went through policy, authorization, the "
          "approval gate, rate limits, and the hash-chained audit log.")
    return 0


def _run_mcp(args) -> int:
    from .mcp_server import serve
    serve(db=args.db, ssh_keys=args.ssh_keys, known_hosts=args.known_hosts,
          allow_unknown_hosts=args.allow_unknown_hosts, aws_region=args.aws_region,
          osv=args.osv, osv_ecosystem=args.osv_ecosystem, kev=args.kev)
    return 0


def _run_report(args) -> int:
    eng = _engine_from_args(args)
    asset_ids = _fleet_asset_ids(eng) if args.all else list(args.assets)
    if not asset_ids:
        print("no assets to report on — pass asset id(s), or --all with registered "
              "ssh-host assets (use --db to point at the DB they were onboarded into)")
        return 1

    print(f"Scanning {len(asset_ids)} asset(s): {', '.join(asset_ids)} ...")
    report, paths = eng.report(asset_ids, out_dir=args.out_dir)

    by_kind = report.counts_by_kind()
    by_sev = report.counts_by_severity()
    print(f"\n{len(report.assets)} asset(s) · {len(report.all_findings)} finding(s) · "
          f"KEV {len(report.kev_findings)}")
    if by_kind:
        print("  by action:   " + ", ".join(f"{k} {v}" for k, v in by_kind.items()))
    if by_sev:
        print("  by severity: " + ", ".join(f"{k} {v}" for k, v in by_sev.items()))
    if report.eol_assets:
        print("  EOL/ESM:     " + ", ".join(a.asset_id for a in report.eol_assets))
    print("\nWritten:")
    for name, path in paths.items():
        print(f"  {name:18} {path}")
    return 0


def _load_instances(args, engine) -> list[dict]:
    if args.from_json:
        import json
        with open(args.from_json, encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("instances", []) if isinstance(data, dict) else list(data)
    # live discovery via a registered cloud account (EC2 + Lightsail)
    ec2, ls = engine.cloud_discover(args.account)
    instances: list[dict] = []
    for r in (ec2, ls):
        if r.ok:
            instances += r.data.get("instances", [])
        else:
            print(f"  discovery warning: {r.summary}")
    return instances


def _run_bulk_onboard(args) -> int:
    import json

    from .onboarding import onboard_instances

    if not args.from_json and not args.account:
        print("specify an input: --from-json FILE or --account ACCOUNT_ID (live discovery)")
        return 1
    if not args.dry_run and not args.db:
        print("refusing to onboard without --db (registrations would not persist); "
              "add --db, or use --dry-run to preview")
        return 1

    engine = _engine_from_args(args)
    instances = _load_instances(args, engine)
    if not instances:
        print("no instances to onboard")
        return 1

    key_map: dict[str, str] = {}
    if args.key_ref_map:
        with open(args.key_ref_map, encoding="utf-8") as fh:
            key_map = json.load(fh)

    existing_ids = {a.asset_id for a in engine.list_assets() if a.kind == "ssh-host"}
    result = onboard_instances(
        instances, engine.registry.register,
        owner=args.owner, granted_by=args.granted_by, attestation_sig=args.attestation_sig,
        environment=args.environment, default_key_ref=args.key_ref, key_ref_by_name=key_map,
        user=args.user, port=args.port, ttl_days=args.ttl_days,
        existing_ids=existing_ids, update=args.update, dry_run=args.dry_run,
    )

    verb = "would register" if args.dry_run else "registered"
    print(f"{verb} {len(result['registered'])} host(s):")
    for r in result["registered"]:
        print(f"  {r['asset_id']:<24} {r['user']}@{r['host']}  env={r['environment']}  "
              f"key_ref={r['key_ref']}  [{r['service']}]")
    if result["skipped"]:
        print(f"\nskipped {len(result['skipped'])}:")
        for s in result["skipped"]:
            print(f"  {s['instance']}: {s['reason']}")
    if args.dry_run:
        print("\n(dry run — nothing written; re-run without --dry-run to persist)")
    return 0


def _run_update_asset(args) -> int:
    from .db import init_db
    from .db.repositories import AssetRepository
    from .onboarding import update_ssh_connection

    fields = {k: v for k, v in
              {"host": args.host, "port": args.port, "user": args.user,
               "key_ref": args.key_ref}.items() if v is not None}
    if not fields:
        print("nothing to update — pass at least one of --host/--port/--user/--key-ref")
        return 1
    repo = AssetRepository(init_db(args.db))
    try:
        asset = update_ssh_connection(repo, args.asset_id, **fields)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}")
        return 1
    conn = asset.connection
    print(f"updated {asset.asset_id} -> {conn.user}@{conn.host}:{conn.port} "
          f"key_ref={conn.key_ref} (changed: {', '.join(sorted(fields))})")
    return 0


def _run_pending(db: str) -> int:
    from .db import init_db
    from .db.repositories import ApprovalRepository
    repo = ApprovalRepository(init_db(db))
    rows = repo.summaries()
    if not rows:
        print("no change-sets recorded")
        return 0
    for r in rows:
        print(f"{r['change_set_id']}  {r['state']:<9} "
              f"blast={r['blast_radius']} ref={r['source_ref']} "
              f"approvers={r['approvers']}/{r['approvals_required']}")
    return 0


def _run_approve(db: str, change_set_id: str, approver: str) -> int:
    from .approval.gate import PersistentApprovalGate
    from .db import init_db
    from .db.repositories import ApprovalRepository
    gate = PersistentApprovalGate(ApprovalRepository(init_db(db)))
    if gate.get(change_set_id) is None:
        print(f"no such change-set: {change_set_id}")
        return 1
    state = gate.decide(change_set_id, approver, approve=True)
    print(f"{change_set_id} -> {state.value}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ai_defense", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="run the local end-to-end demo")
    p_mcp = sub.add_parser("mcp", help="run the MCP server over stdio (needs the 'mcp' extra)")
    _add_engine_args(p_mcp)

    p_report = sub.add_parser(
        "report", help="scan asset(s) and write vulnerability reports to local files")
    p_report.add_argument("assets", nargs="*",
                          help="asset ids to report on (omit and use --all for the fleet)")
    p_report.add_argument("--all", action="store_true",
                          help="report across all registered ssh-host assets (fleet sweep)")
    p_report.add_argument("--out-dir", default=None,
                          help="directory to write into (default: ./reports/<timestamp>)")
    _add_engine_args(p_report)

    p_bulk = sub.add_parser(
        "bulk-onboard",
        help="register discovered cloud instances as ssh-host assets (operator)")
    g_in = p_bulk.add_argument_group("input (choose one)")
    g_in.add_argument("--from-json",
                      help="JSON file of discovered instances ({\"instances\":[...]} or a list)")
    g_in.add_argument("--account",
                      help="registered cloud account id -> discover instances live")
    p_bulk.add_argument("--owner", required=True)
    p_bulk.add_argument("--granted-by", required=True)
    p_bulk.add_argument("--attestation-sig", required=True,
                        help="the operator's authorization attestation for these hosts")
    p_bulk.add_argument("--environment", default=None,
                        help="environment tag for all (default: each instance's 'env' tag "
                             "else 'unknown')")
    p_bulk.add_argument("--key-ref", default=None,
                        help="vault key ref for all hosts (key already stored in the vault)")
    p_bulk.add_argument("--key-ref-map", default=None,
                        help="JSON file mapping asset_id -> key_ref (per-host keys)")
    p_bulk.add_argument("--user", default=None,
                        help="SSH user override (default: inferred from platform/blueprint)")
    p_bulk.add_argument("--port", type=int, default=22)
    p_bulk.add_argument("--ttl-days", type=int, default=90)
    p_bulk.add_argument("--update", action="store_true",
                        help="re-register hosts that already exist (default: skip them)")
    p_bulk.add_argument("--dry-run", action="store_true", help="preview without writing")
    _add_engine_args(p_bulk)

    p_update = sub.add_parser(
        "update-asset",
        help="correct an ssh-host's connection info (host/port/user/key_ref) without "
             "re-onboarding; preserves the authorization/attestation")
    p_update.add_argument("--db", required=True, help="DB URL the asset is registered in")
    p_update.add_argument("--asset-id", required=True)
    p_update.add_argument("--host", default=None, help="new address (IP/DNS)")
    p_update.add_argument("--port", type=int, default=None)
    p_update.add_argument("--user", default=None, help="new SSH login user")
    p_update.add_argument("--key-ref", default=None,
                          help="new vault key reference (key already stored in the vault)")

    p_pending = sub.add_parser("pending", help="list approval change-sets in a DB")
    p_pending.add_argument("--db", required=True)

    p_approve = sub.add_parser("approve", help="operator: approve a pending change-set")
    p_approve.add_argument("--db", required=True)
    p_approve.add_argument("--change-set", required=True)
    p_approve.add_argument("--approver", default="operator")

    args = parser.parse_args(argv)

    if args.command == "demo":
        return _run_demo()
    if args.command == "mcp":
        return _run_mcp(args)
    if args.command == "report":
        return _run_report(args)
    if args.command == "bulk-onboard":
        return _run_bulk_onboard(args)
    if args.command == "update-asset":
        return _run_update_asset(args)
    if args.command == "pending":
        return _run_pending(args.db)
    if args.command == "approve":
        return _run_approve(args.db, args.change_set, args.approver)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
