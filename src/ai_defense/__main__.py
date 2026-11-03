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


def _run_mcp() -> int:
    from .mcp_server import serve
    serve()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ai_defense", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="run the local end-to-end demo")
    sub.add_parser("mcp", help="run the MCP server over stdio (needs the 'mcp' extra)")
    args = parser.parse_args(argv)

    if args.command == "demo":
        return _run_demo()
    if args.command == "mcp":
        return _run_mcp()
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
