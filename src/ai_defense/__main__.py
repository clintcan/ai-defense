"""`python -m ai_defense` — operator entrypoint.

Subcommands:
  demo   Run the full lifecycle locally against the demo backends (no infra).
"""

from __future__ import annotations

import argparse


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
          osv=args.osv, osv_ecosystem=args.osv_ecosystem)
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
    p_mcp.add_argument("--db", default=None,
                       help="DB URL for a durable engine shared with the operator CLI")
    p_mcp.add_argument("--ssh-keys", default=None,
                       help="key directory -> use the real SSH backend (needs 'ssh' extra)")
    p_mcp.add_argument("--known-hosts", default=None, help="known_hosts file for host-key checks")
    p_mcp.add_argument("--allow-unknown-hosts", action="store_true",
                       help="accept unknown SSH host keys (trust on first use; less safe)")
    p_mcp.add_argument("--aws-region", default=None,
                       help="default AWS region -> use live boto3 for cloud tools "
                            "(needs 'aws' extra; creds resolved from the vault)")
    p_mcp.add_argument("--osv", action="store_true",
                       help="pull real advisories from OSV.dev for observed packages")
    p_mcp.add_argument("--osv-ecosystem", default="Debian",
                       help="OSV ecosystem for queries (default: Debian)")

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
    if args.command == "pending":
        return _run_pending(args.db)
    if args.command == "approve":
        return _run_approve(args.db, args.change_set, args.approver)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
