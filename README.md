# AI Defense

Defensive orchestration & remediation harness. See [`CLAUDE.md`](./CLAUDE.md)
for the full architecture and security model.

**Governing rule:** the LLM is a *planner*, never an *actor*. It proposes typed
intents; the non-LLM **toolset** layer validates against policy, resolves
secrets from the vault at execution time, and executes. Credentials never reach
the model, and every remote-mutating action is human-approved.

## Layout

```
src/ai_defense/
  planner/    LLM-facing layer — emits Intents, sees redacted results only
  toolset/    enforcement core — intents, validators, policy engine, registry
  vault/      secrets (ciphertext + key refs; resolved at call time)
  registry/   asset registry & signed authorization ledger
  cloud/      per-provider API adapters (aws/gcp/azure), narrow & typed
  ssh/        approved command execution: catalog (allowlist), denylist, executor
  scanner/    authenticated READ-ONLY detection (OpenSCAP/OVAL, pkg query modes)
  vuln/       advisory feeds, correlation, remediation planner
  approval/   human approval gate (canary -> fleet; N-of-M; expiry)
  audit/      append-only, tamper-evident log
  db/         persistence models
config/       policy.example.yaml, assets.example.yaml (copy to git-ignored real files)
tests/        denylist + authorization safety tests
```

## Status

Working vertical slice. Implemented and tested end to end:

- **Toolset dispatch pipeline** — validate → capability check → authorize →
  policy → approval gate → resolve secrets → execute → redact → audit.
- **SSH executor** on a pluggable transport with catalog-only commands,
  denylist, dry-run-first, output caps, and a first `mutating` tool
  (`patch.apply_security_update`).
- **Persistence** (`db/`, SQLAlchemy 2.0) — assets/authorizations, secret
  *references* (ciphertext only), approvals + votes, scan findings, advisories/
  remediations, and a durable hash-chained audit log that still `verify()`s
  after reload.

- **Policy rate limiting** — `per_host_changes_per_hour` and `fleet_concurrency`
  enforced on mutating changes via an atomic check-and-reserve `RateLimiter`.
- **AWS adapter (read-only discovery)** — EC2 instance inventory, SSM patch
  state, and Lightsail instances behind an injected client seam (boto3 is an
  optional `[aws]` extra); exposed as `READ_ONLY` discovery tools that resolve
  the AWS credential per call from the vault. Instances are normalized to one
  stable shape tagged by `service` (`ec2` / `lightsail`). The credential
  descriptor can name a profile, use the default provider chain (instance role /
  env / SSO — piggybacking on the AWS CLI's own config so nothing is stored), or
  carry static keys, optionally layering an assume-role on top.

- **Vulnerability → remediation planner** — the authenticated scanner (on a
  pluggable read-only `HostInspector`) produces observed `HostFindings`;
  advisories (normalized `Advisory`, pluggable feeds) are correlated against
  that observed state with a best-effort version comparator; the planner emits a
  prioritized plan (CISA KEV → CVSS): **patch available → a dispatchable patch
  intent; no patch → a labeled-temporary mitigation with a tracking follow-up;
  neither → escalate**. Proven end to end: scan → plan → approved, dry-run,
  audited remediation on a canary.

- **AWS protective slice** — `snapshot_before_change` as a `PROTECTIVE`
  (autonomous) tool: EBS snapshots of every attached volume for EC2, and the
  separate instance-snapshot API for Lightsail. Returns a rollback hint for the
  audit trail / a remediation item's rollback payload.

- **Remediation workflow** — `RemediationWorkflow` sequences an optional
  protective snapshot before the approval-gated patch (snapshot once; abort the
  patch if a requested snapshot fails; retain it through approval/failure), and
  exposes a deliberate, approval-gated `CLEANUP` to delete the snapshot once the
  fix is confirmed stable.

- **AWS SSM patch baseline (write)** — `apply_patch_baseline` runs
  AWS-RunPatchBaseline, scanning (read-only) before installing, as a `MUTATING`
  approval-gated tool whose blast radius is the target instance count.

- **Asset onboarding** — `ssh-host` assets carry `ConnectionInfo`
  (host/port/user + vault `key_ref`). Register a VPS out-of-band via the
  `register-vps` CLI (`python -m ai_defense.onboarding`), or let the LLM propose
  it through the approval-gated `asset.register` tool (`ONBOARD` action class;
  key stays in the vault, intent must target a pre-registered control-plane
  asset).

- **Registry-resolved SSH connections** — the patch tool takes only
  `{asset_id, package}`; host/user/port/key_ref come from the authorized asset
  in the registry (re-checked at resolve time), so a command can never be aimed
  at an arbitrary host or key, and the planner never handles connection details.

- **Real SSH backend** — `composition.build_ssh_engine(key_dir=...)` wires a
  paramiko transport (host-key verification on by default), a file-backed vault
  (keys under `key_dir`, referenced by `key_ref`, never in the DB), and a
  read-only SSH host inspector (`dpkg-query`). Run it behind the chat server with
  `ai-defense mcp --ssh-keys <dir> [--known-hosts <file>]`. Needs the `ssh` extra
  (`pip install -e ".[ssh]"`).

- **AWS in chat (live)** — `--aws-region` makes the cloud tools use real boto3
  (CLI-profile auth; creds resolved from the vault by `credential_ref`, no keys
  stored). Cloud accounts are onboarded (approval-gated) and managed from chat
  via `onboard_cloud_account`, `cloud_discover` (EC2 + Lightsail),
  `cloud_patch_state`, and `cloud_remediate` (SSM baseline, approval-gated).

Still stubbed: OSV/NVD advisory clients and other cloud providers (GCP/Azure) —
the seams are in place. Run `pytest` and `ruff check src tests`.

## Install & run

One-shot install into a local virtualenv (creates `.venv`, installs the package,
runs the tests and the demo):

```bash
./install.sh                 # Linux/macOS  (optional: ./install.sh dev,aws,mcp)
```
```powershell
.\install.ps1                # Windows      (optional: .\install.ps1 -Extras "dev,aws,mcp")
```

Or manually:

```bash
pip install -r requirements-dev.txt   # or: pip install -e ".[dev,mcp]"
pip install -e .
python -m ai_defense demo             # full lifecycle on simulated backends, no infra
pytest                                # test suite
```

The demo onboards a VPS (approval-gated), scans it, plans a KEV-first
remediation, patches the top finding (approval-gated, dry-run first), and prints
the hash-chained audit log — all through the real dispatcher, so you see policy,
authorization, the approval gate, rate limits, and redaction in action. The
`composition.build_demo_engine()` wiring differs from production only in the
backends it injects (simulated vault/SSH/AWS vs. real ones).

## Chat / MCP

Drive it from an MCP client (e.g. Claude Desktop/Code) in plain language:

```bash
pip install -e ".[mcp]"
python -m ai_defense mcp            # MCP server over stdio
```

Tools exposed: `list_assets`, `scan`, `plan`, `remediate`, `approve_change`,
`audit_tail`. Every call routes through the dispatcher, so the model proposes and
the toolset enforces: a `remediate` returns *pending* with a `change_set_id`
until a human calls `approve_change`, and the MCP client also prompts the human
before any tool runs. Example client config:

### Durable, out-of-band approvals

With a `PersistentApprovalGate` (a `session_factory` passed to
`build_demo_engine`), approvals are stored in the DB — they survive restarts and
are shared across processes, so an operator can approve from the terminal while
the chat/MCP session waits:

```bash
python -m ai_defense pending --db sqlite+pysqlite:///ai.db          # list change-sets
python -m ai_defense approve --db sqlite+pysqlite:///ai.db \
  --change-set cs_... --approver you                                # authorize one
```

### Durable engine (shared across processes)

Give the MCP server a DB and it uses `build_engine(session_factory=...)`: the
asset registry, approvals, and audit log are all persistent and **shared with
the operator CLI**. Onboard a VPS with `register-vps`, point the server at the
same DB, and it sees the asset live; approvals granted in the terminal are
honoured in chat; everything survives a restart.

```bash
python -m ai_defense mcp --db sqlite+pysqlite:///ai.db
```


```json
{ "mcpServers": { "ai-defense": { "command": "python", "args": ["-m", "ai_defense", "mcp"] } } }
```

## Non-negotiables (enforced in code review)

1. Only registered, authorized assets — never arbitrary/third-party systems.
2. The model never receives secrets.
3. No free-form remote command execution by the model.
4. Every remote-mutating action is human-approved and audit-logged.
5. Default deny; new provider methods / command templates are unreachable until
   wrapped, reviewed, and allowlisted.
