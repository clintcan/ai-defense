"""`python -m ai_defense` — operator entrypoint.

Subcommands:
  demo      Run the full lifecycle locally against the demo backends (no infra).
  mcp       Run the MCP server over stdio.
  report    Scan asset(s) and write vulnerability reports to local files.
  pending   List approval change-sets in a DB.
  approve   Approve a pending change-set.
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
    if args.command == "pending":
        return _run_pending(args.db)
    if args.command == "approve":
        return _run_approve(args.db, args.change_set, args.approver)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
