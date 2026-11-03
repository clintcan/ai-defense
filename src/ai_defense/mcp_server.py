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

import os
from typing import Any

from .composition import Engine, build_demo_engine
from .registry.assets import Asset
from .scanner.scanner import HostFindings
from .upgrade.preflight import OsUpgradeReport
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
        "name": "upgrade_preflight",
        "description": "Read-only OS-upgrade eligibility report for the given assets: "
                       "current release and support status (supported/ESM/EOL), the "
                       "supported in-place target and full upgrade path, and any blockers "
                       "(pending reboot, held/broken packages, low disk). Changes nothing; "
                       "it informs the human decision for an EOL OS.",
        "inputSchema": {
            "type": "object",
            "properties": {"asset_ids": {"type": "array", "items": {"type": "string"}}},
            "required": ["asset_ids"],
        },
    },
    {
        "name": "report",
        "description": "Generate vulnerability reports for the given assets and write them "
                       "to local files: an executive summary (Markdown), a technical report "
                       "(Markdown), a generic findings JSON, and a DefectDojo Generic "
                       "Findings Import JSON. Read-only; returns the written file paths and "
                       "a summary (never the full content). Files stay local.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_ids": {"type": "array", "items": {"type": "string"}},
                "out_dir": {"type": "string",
                            "description": "directory to write into (default: "
                                           "./reports/<timestamp>)"},
            },
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
    {
        "name": "onboard_cloud_account",
        "description": "Register a cloud account (e.g. AWS) so its instances can be "
                       "managed. Approval-gated; the AWS credential must already be in "
                       "the vault, referenced by credential_ref (never the keys here).",
        "inputSchema": {
            "type": "object",
            "required": ["account_id", "credential_ref", "owner", "environment",
                         "granted_by"],
            "properties": {
                "account_id": {"type": "string"},
                "credential_ref": {"type": "string"},
                "owner": {"type": "string"},
                "environment": {"type": "string"},
                "granted_by": {"type": "string"},
                "provider": {"type": "string"},
            },
        },
    },
    {
        "name": "cloud_regions",
        "description": "List the regions available to a registered cloud account "
                       "(EC2 enabled regions + Lightsail regions). Read-only.",
        "inputSchema": {
            "type": "object",
            "required": ["account_id"],
            "properties": {"account_id": {"type": "string"}},
        },
    },
    {
        "name": "cloud_discover",
        "description": "List EC2 and Lightsail instances in a registered cloud "
                       "account (Lightsail across all regions). Read-only.",
        "inputSchema": {
            "type": "object",
            "required": ["account_id"],
            "properties": {"account_id": {"type": "string"}},
        },
    },
    {
        "name": "cloud_patch_state",
        "description": "SSM patch compliance for the given EC2 instances in an account "
                       "(read-only); flags the non-compliant ones.",
        "inputSchema": {
            "type": "object",
            "required": ["account_id", "instance_ids"],
            "properties": {
                "account_id": {"type": "string"},
                "instance_ids": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
    {
        "name": "cloud_remediate",
        "description": "Apply an SSM patch baseline to EC2 instances (scans first, "
                       "then installs). Returns pending with a change_set_id until a "
                       "human approves; re-call after approval to apply.",
        "inputSchema": {
            "type": "object",
            "required": ["account_id", "instance_ids"],
            "properties": {
                "account_id": {"type": "string"},
                "instance_ids": {"type": "array", "items": {"type": "string"}},
                "baseline": {"type": "string"},
            },
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
    return {"asset_id": f.asset_id, "ecosystem": f.ecosystem,
            "installed_packages": f.installed_packages,
            "applied_patches": f.applied_patches,
            "misconfigurations": f.misconfigurations}


def _report_json(r: OsUpgradeReport) -> dict:
    return {"asset_id": r.asset_id, "verdict": r.verdict.value,
            "current_os": r.current_os, "support_status": r.support_status,
            "target_version": r.target_version, "target_codename": r.target_codename,
            "path": r.path,
            "blockers": [{"code": b.code, "detail": b.detail} for b in r.blockers],
            "notes": r.notes, "source_ref": r.source_ref}


def _item_json(it: RemediationItem) -> dict:
    return {"cve_id": it.cve_id, "asset_id": it.asset_id, "package": it.package,
            "kind": it.kind.value, "priority": it.priority,
            "cvss": it.cvss, "kev": it.kev,
            "installed_version": it.installed_version, "fixed_version": it.fixed_version,
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

        if name == "upgrade_preflight":
            reports = engine.upgrade_preflight(list(args["asset_ids"]))
            return {"reports": [_report_json(r) for r in reports]}

        if name == "report":
            report, paths = engine.report(list(args["asset_ids"]),
                                          out_dir=args.get("out_dir"))
            return {
                "out_dir": os.path.dirname(paths["generic_json"]),
                "files": paths,
                "summary": {
                    "assets": len(report.assets),
                    "findings": len(report.all_findings),
                    "kev": len(report.kev_findings),
                    "by_kind": report.counts_by_kind(),
                    "by_severity": report.counts_by_severity(),
                    "eol_assets": [a.asset_id for a in report.eol_assets],
                },
            }

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

        if name == "onboard_cloud_account":
            res = engine.onboard_cloud_account(**args)
            return _tool_result_json(res)

        if name == "cloud_regions":
            return _tool_result_json(engine.cloud_regions(args["account_id"]))

        if name == "cloud_discover":
            ec2, ls = engine.cloud_discover(args["account_id"])
            instances = []
            for r in (ec2, ls):
                if r.ok:
                    instances += r.data.get("instances", [])
            return {"account_id": args["account_id"], "instances": instances,
                    "errors": [r.summary for r in (ec2, ls) if not r.ok]}

        if name == "cloud_patch_state":
            res = engine.cloud_patch_state(args["account_id"], list(args["instance_ids"]))
            return _tool_result_json(res)

        if name == "cloud_remediate":
            res = engine.cloud_remediate(args["account_id"], list(args["instance_ids"]),
                                         baseline=args.get("baseline"))
            out = _tool_result_json(res)
            if res.data.get("approval_state") == "pending":
                out["change_set_id"] = res.data.get("change_set_id")
                out["next"] = "ask the operator to approve, then call cloud_remediate again"
            return out

        return {"error": f"unknown tool: {name}"}
    except KeyError as exc:
        return {"error": f"missing argument: {exc}"}


def _tool_result_json(res) -> dict:
    return {"ok": res.ok, "summary": res.summary, "data": res.data}


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


# --- stdio server (lazy mcp import; targets the mcp 2.x MCPServer API) ----

_DESCRIPTIONS = {t["name"]: t["description"] for t in TOOLS}


def _engine_for(engine: Engine | None, db: str | None, *, ssh_keys: str | None = None,
                known_hosts: str | None = None, allow_unknown_hosts: bool = False,
                aws_region: str | None = None, osv: bool = False,
                osv_ecosystem: str = "Debian", kev: bool = False) -> Engine:
    if engine is not None:
        return engine
    sf = None
    if db is not None:
        from .db import init_db
        sf = init_db(db)
    feed = None
    if osv:
        from .vuln.osv import OsvFeed
        feed = OsvFeed(ecosystem=osv_ecosystem)
    if ssh_keys is not None:
        from .composition import build_ssh_engine
        return build_ssh_engine(key_dir=ssh_keys, session_factory=sf,
                                known_hosts=known_hosts,
                                allow_unknown_hosts=allow_unknown_hosts,
                                aws_region=aws_region, advisory_feed=feed,
                                enrich_kev=kev)
    return build_demo_engine(session_factory=sf, aws_region=aws_region,
                             advisory_feed=feed, enrich_kev=kev)


def build_mcp_server(engine: Engine):  # pragma: no cover - exercised via QA/import-gated test
    """Build an mcp 2.x ``MCPServer`` with our tools registered.

    Each tool is a thin typed function delegating to ``handle_call``; the SDK
    derives the input schema from the function signature. Separated from
    ``serve`` so the registration can be validated without the stdio loop."""
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("ai-defense", instructions=(
        "Defensive patch orchestration. Propose actions; the toolset enforces "
        "policy, authorization, approval, rate limits and audit. Mutating work "
        "returns a pending change_set_id until a human approves."))

    def list_assets() -> dict:
        return handle_call(engine, "list_assets", {})

    def scan(asset_ids: list[str]) -> dict:
        return handle_call(engine, "scan", {"asset_ids": asset_ids})

    def plan(asset_ids: list[str]) -> dict:
        return handle_call(engine, "plan", {"asset_ids": asset_ids})

    def upgrade_preflight(asset_ids: list[str]) -> dict:
        return handle_call(engine, "upgrade_preflight", {"asset_ids": asset_ids})

    def report(asset_ids: list[str], out_dir: str | None = None) -> dict:
        return handle_call(engine, "report",
                           {"asset_ids": asset_ids, "out_dir": out_dir})

    def remediate(asset_id: str, package: str, snapshot: bool = False) -> dict:
        return handle_call(engine, "remediate",
                           {"asset_id": asset_id, "package": package, "snapshot": snapshot})

    def approve_change(change_set_id: str, approver: str = "operator") -> dict:
        return handle_call(engine, "approve_change",
                           {"change_set_id": change_set_id, "approver": approver})

    def audit_tail(n: int = 20) -> dict:
        return handle_call(engine, "audit_tail", {"n": n})

    def onboard_cloud_account(account_id: str, credential_ref: str, owner: str,
                              environment: str, granted_by: str,
                              provider: str = "aws") -> dict:
        return handle_call(engine, "onboard_cloud_account", {
            "account_id": account_id, "credential_ref": credential_ref, "owner": owner,
            "environment": environment, "granted_by": granted_by, "provider": provider})

    def cloud_regions(account_id: str) -> dict:
        return handle_call(engine, "cloud_regions", {"account_id": account_id})

    def cloud_discover(account_id: str) -> dict:
        return handle_call(engine, "cloud_discover", {"account_id": account_id})

    def cloud_patch_state(account_id: str, instance_ids: list[str]) -> dict:
        return handle_call(engine, "cloud_patch_state",
                           {"account_id": account_id, "instance_ids": instance_ids})

    def cloud_remediate(account_id: str, instance_ids: list[str],
                        baseline: str | None = None) -> dict:
        return handle_call(engine, "cloud_remediate", {
            "account_id": account_id, "instance_ids": instance_ids, "baseline": baseline})

    for fn in (list_assets, scan, plan, upgrade_preflight, report, remediate,
               approve_change, audit_tail, onboard_cloud_account, cloud_regions,
               cloud_discover, cloud_patch_state, cloud_remediate):
        server.add_tool(fn, name=fn.__name__, description=_DESCRIPTIONS[fn.__name__])
    return server


def serve(engine: Engine | None = None, *, db: str | None = None,
          ssh_keys: str | None = None, known_hosts: str | None = None,
          allow_unknown_hosts: bool = False,
          aws_region: str | None = None, osv: bool = False,
          osv_ecosystem: str = "Debian", kev: bool = False) -> None:  # pragma: no cover
    """Run the MCP server over stdio. Requires the ``mcp`` extra (>=2).

    With ``db`` the engine is durable and shares assets/approvals with the
    operator CLI. With ``ssh_keys`` it uses the real SSH backend (paramiko). With
    ``aws_region`` it uses live boto3 for the cloud tools. With ``osv`` it pulls
    real advisories from OSV.dev for the packages a scan observes."""
    eng = _engine_for(engine, db, ssh_keys=ssh_keys, known_hosts=known_hosts,
                      allow_unknown_hosts=allow_unknown_hosts, aws_region=aws_region,
                      osv=osv, osv_ecosystem=osv_ecosystem, kev=kev)
    build_mcp_server(eng).run("stdio")
