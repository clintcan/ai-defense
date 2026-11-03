"""MCP server — drive the engine from an MCP client (e.g. Claude Desktop/Code).

Exposes a focused set of operations mapped to the ``Engine``. Each call still
goes through the dispatcher, so policy, authorization, the approval gate, rate
limits, redaction, and the audit log all apply — the model proposes, the toolset
enforces. Mutating work returns a *pending* result with a change-set id; a human
authorizes it with ``approve_change`` (and the MCP client also prompts the human
before any tool runs, a second human gate).

The tool manifest (``TOOLS``) and the call handler (``handle_call``) are pure and
unit-tested; ``serve`` wires them to the ``mcp`` SDK over stdio and is imported
lazily so the package works without that optional dependency.
"""

from __future__ import annotations

from typing import Any

from .composition import Engine, build_demo_engine
from .registry.assets import Asset
from .scanner.scanner import HostFindings
from .vuln.planner import RemediationItem

TOOLS: list[dict[str, Any]] = [
    {
        "name": "list_assets",
        "description": "List registered, authorized assets (inventory).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "scan",
        "description": "Read-only scan of the given assets; returns observed "
                       "installed packages and misconfigurations.",
        "inputSchema": {
            "type": "object",
            "properties": {"asset_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["asset_ids"],
        },
    },
    {
        "name": "plan",
        "description": "Scan the given assets and return a prioritized remediation "
                       "plan (CISA KEV first): patch / mitigation / escalate.",
        "inputSchema": {
            "type": "object",
            "properties": {"asset_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["asset_ids"],
        },
    },
    {
        "name": "remediate",
        "description": "Apply a security update for a package on an asset. Returns a "
                       "pending result with a change_set_id until a human approves; "
                       "re-call after approval to apply. Dry-runs before applying.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_id": {"type": "string"},
                "package": {"type": "string"},
                "snapshot": {"type": "boolean",
                             "description": "take a cloud snapshot first (cloud assets)"},
            },
            "required": ["asset_id", "package"],
        },
    },
    {
        "name": "approve_change",
        "description": "Human authorization for a pending change-set (the operator "
                       "approving a proposed mutating action).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "change_set_id": {"type": "string"},
                "approver": {"type": "string"},
            },
            "required": ["change_set_id"],
        },
    },
    {
        "name": "audit_tail",
        "description": "Return the most recent audit-log records and whether the "
                       "tamper-evident chain verifies.",
        "inputSchema": {
            "type": "object",
            "properties": {"n": {"type": "integer"}},
        },
    },
]


def tool_names() -> list[str]:
    return [t["name"] for t in TOOLS]


# --- serializers ---------------------------------------------------------

def _asset_json(a: Asset) -> dict:
    return {"asset_id": a.asset_id, "kind": a.kind, "owner": a.owner,
            "environment": a.environment,
            "host": a.connection.host if a.connection else None}


def _findings_json(f: HostFindings) -> dict:
    return {"asset_id": f.asset_id, "installed_packages": f.installed_packages,
            "applied_patches": f.applied_patches,
            "misconfigurations": f.misconfigurations}


def _item_json(it: RemediationItem) -> dict:
    return {"cve_id": it.cve_id, "asset_id": it.asset_id, "package": it.package,
            "kind": it.kind.value, "priority": it.priority,
            "requires_human": it.requires_human, "note": it.note,
            "tracking": it.tracking}


# --- call handler (pure) -------------------------------------------------

def handle_call(engine: Engine, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one MCP tool call to the engine. Returns a JSON-serializable
    dict. Unknown tools and bad arguments return an ``error`` field rather than
    raising, so the model gets a usable message."""
    args = arguments or {}
    try:
        if name == "list_assets":
            return {"assets": [_asset_json(a) for a in engine.list_assets()]}

        if name == "scan":
            inv = engine.scan(list(args["asset_ids"]))
            return {"findings": [_findings_json(f) for f in inv]}

        if name == "plan":
            inv = engine.scan(list(args["asset_ids"]))
            return {"plan": [_item_json(it) for it in engine.plan(inv)]}

        if name == "remediate":
            return _remediate(engine, args["asset_id"], args["package"],
                              bool(args.get("snapshot", False)))

        if name == "approve_change":
            state = engine.approve(args["change_set_id"], args.get("approver", "operator"))
            return {"change_set_id": args["change_set_id"], "state": state.value}

        if name == "audit_tail":
            n = int(args.get("n", 20))
            recs = engine.audit_tail(n)
            return {"verified": engine.audit_ok(),
                    "records": [{"event": r.event,
                                 "tool": r.payload.get("tool"),
                                 "reason": r.payload.get("reason"),
                                 "ts": r.ts.isoformat()} for r in recs]}

        return {"error": f"unknown tool: {name}"}
    except KeyError as exc:
        return {"error": f"missing argument: {exc}"}


def _remediate(engine: Engine, asset_id: str, package: str, snapshot: bool) -> dict:
    inv = engine.scan([asset_id])
    item = next((it for it in engine.plan(inv)
                 if it.asset_id == asset_id and it.package == package and it.intent), None)
    if item is None:
        return {"status": "no_patch_available",
                "detail": f"no patch remediation found for {package} on {asset_id} "
                          f"(it may need a mitigation/escalation — see plan)"}
    result = engine.remediate(item, snapshot=snapshot)
    out: dict[str, Any] = {"status": result.status, "cve_id": item.cve_id,
                           "snapshot_ids": result.snapshot_ids}
    if result.patch is not None:
        out["summary"] = result.patch.summary
        if result.patch.data.get("approval_state") == "pending":
            out["change_set_id"] = result.patch.data.get("change_set_id")
            out["next"] = "ask the operator to approve, then call remediate again"
    return out


# --- stdio server (lazy mcp import) --------------------------------------

def serve(engine: Engine | None = None) -> None:  # pragma: no cover - needs mcp + stdio
    """Run the MCP server over stdio. Requires the ``mcp`` extra."""
    import json

    import anyio
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool

    eng = engine or build_demo_engine()
    server = Server("ai-defense")

    @server.list_tools()
    async def _list_tools() -> list[Tool]:
        return [Tool(name=t["name"], description=t["description"],
                     inputSchema=t["inputSchema"]) for t in TOOLS]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> list[TextContent]:
        result = handle_call(eng, name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2, default=str))]

    async def _main() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_main)
