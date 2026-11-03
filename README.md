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

Scaffold. Modules define the component boundaries and interfaces; execution
pipelines raise `NotImplementedError` pending implementation. Two safety
behaviors already have tests: the destructive-command denylist and the
unregistered/expired-authorization refusal.

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
