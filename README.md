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
- **AWS adapter (read-only discovery)** — EC2 instance inventory and SSM patch
  state behind an injected client seam (boto3 is an optional `[aws]` extra);
  exposed as `READ_ONLY` discovery tools that resolve the AWS credential per
  call from the vault.

Still stubbed: AWS protective/write ops (snapshot, patch-baseline), other cloud
providers, the vuln feeds/planner, and the scanner internals. Run `pytest`
(72 tests) and `ruff check src tests`.

## Dev

```bash
pip install -e ".[dev]"
pytest
```

## Non-negotiables (enforced in code review)

1. Only registered, authorized assets — never arbitrary/third-party systems.
2. The model never receives secrets.
3. No free-form remote command execution by the model.
4. Every remote-mutating action is human-approved and audit-logged.
5. Default deny; new provider methods / command templates are unreachable until
   wrapped, reviewed, and allowlisted.
