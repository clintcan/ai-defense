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

Still stubbed: SSH remediation resolving its connection from the registry (patch
tools still take host/key_ref in params), other AWS services and cloud providers
(GCP/Azure), and real advisory-feed / host-inspector / boto3 clients (the seams
are in place; implementations are injected in tests). Run `pytest` (111 tests)
and `ruff check src tests`.

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
