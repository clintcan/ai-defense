# AI Defense — Orchestration & Remediation Harness

## What this project is

A **defensive security operations platform** for infrastructure you own or are
explicitly authorized to administer. Its job is to shorten the time between
*"a vulnerability is disclosed"* and *"every affected host is patched or
mitigated."*

It does three things:

1. **Inventory & orchestrate** assets across multiple cloud providers (AWS, GCP,
   Azure, etc.) through their official APIs.
2. **Connect to managed servers** over SSH to apply patches and mitigations —
   every remote-changing action gated behind human approval.
3. **Match known vulnerabilities to your fleet** and drive remediation: apply the
   vendor patch when one exists, or apply the published mitigation/workaround
   when a patch has not shipped yet.

This is an **administration and remediation accelerator**. It operates only on
assets the operator has registered and attested authorization for. It is not an
offensive tool and must never be pointed at third-party systems.

---

## Core security model

The single most important design rule:

> **The LLM is a planner, not an actor. It never holds credentials and never
> executes a command directly.**

The model proposes *intents* ("install the vendor update for CVE-XXXX on hosts
tagged `web-prod`"). A separate, non-LLM **toolset layer** validates the intent
against policy, resolves credentials from the vault, executes against the
provider/host, and returns structured results. The model sees results and the
command *that would run*, never the secrets behind it.

```
┌──────────────┐   intent (JSON)   ┌───────────────────┐
│   LLM /      │ ────────────────► │  Toolset Layer     │
│   Planner    │                   │  (policy engine,   │
│              │ ◄──────────────── │   validators,      │
└──────────────┘  structured result│   executors)       │
                                    └─────────┬─────────┘
                                              │ resolves at call time
                              ┌───────────────┼────────────────┐
                              ▼               ▼                ▼
                       ┌──────────┐    ┌────────────┐   ┌─────────────┐
                       │  Secrets │    │ Cloud API  │   │ SSH Executor│
                       │  Vault   │    │ Adapters   │   │ (approved)  │
                       └──────────┘    └────────────┘   └─────────────┘
```

### Trust boundaries

- **The model is untrusted with secrets.** Credentials, private keys, API
  tokens never appear in prompts, tool arguments, tool results, or logs the
  model can read. The toolset injects them at execution time and redacts them
  from everything returned.
- **The toolset is the policy enforcement point.** Allow/deny lists, approval
  requirements, rate limits, and blast-radius checks live here — not in the
  prompt. A jailbroken or confused model still cannot exceed what the toolset
  permits.
- **Humans own all state-changing remote actions.** Read-only discovery can run
  autonomously (subject to policy). Anything that mutates a server or cloud
  resource requires an explicit, logged human approval.

---

## Components

### 1. Asset registry & authorization ledger
- Every managed host/account is registered with: owner, environment tag,
  authorization attestation, and the approval policy that applies to it.
- Actions can only target **registered** assets. An unregistered target is a
  hard error, not a prompt the model can argue past.
- Authorization attestations are signed and timestamped; expired attestations
  disable write actions on that asset until renewed.

### 2. Secrets vault (credentials never touch the LLM)
- Backed by a real secrets manager (HashiCorp Vault / AWS Secrets Manager /
  age-encrypted store), not plaintext config.
- Stores: cloud API credentials, SSH private keys / certificates, sudo
  escalation secrets.
- Credentials are stored encrypted at rest; the DB holds only ciphertext +
  key references. The toolset fetches and decrypts **at call time**, uses the
  secret in-process, and never returns it.
- Prefer short-lived credentials: cloud STS / OIDC federation, SSH
  **certificates** with short TTLs over long-lived static keys.
- All secret reads are audit-logged (who/what/when/why), with the secret value
  itself never logged.

### 3. Cloud provider adapters (API-only toolset)
- One adapter per provider, each exposing a **narrow, typed set of tools** — the
  only surface the model can reach. Examples:
  - `cloud.list_instances(provider, account, filters)` — read-only
  - `cloud.describe_patch_state(instance_ids)` — read-only
  - `cloud.snapshot_before_change(instance_id)` — protective
  - `cloud.apply_patch_baseline(instance_ids, baseline)` — **write, approval-gated**
- No generic "run arbitrary API call" tool. If the SDK method isn't wrapped as a
  reviewed tool, the model can't call it.
- Each write tool declares its blast radius so the policy engine and the human
  approver can see exactly how many assets are affected.

### 3a. Dispatch pipeline (the one path every intent travels)
Every intent the planner submits goes through a single enforcement pipeline in
the toolset; there is no other way to reach a provider or host:

1. **Validate** the intent against the registered tool's schema.
2. **Capability check** — each tool declares a capability (`read_only`,
   `protective`, `mutating`) and the action classes it may run under. A
   *mutating* tool can never be dispatched under an autonomous (read-only)
   action class, so it cannot bypass approval by being mislabeled. Enforced
   before policy, independent of it.
3. **Authorize targets** — every target must be a registered asset with a valid,
   unexpired authorization attestation.
4. **Policy** — blast-radius caps, autonomy, and approval requirement.
5. **Approval gate** — anything not autonomous waits for human approval (N-of-M,
   canary→fleet precondition, expiry).
6. **Rate limit** — for mutating changes, atomic check-and-reserve against
   `per_host_changes_per_hour` and `fleet_concurrency`; the concurrency slot is
   held until execution finishes (released in a `finally`).
7. **Resolve secrets** from the vault, **execute**, **redact** every resolved
   secret from the result, **audit** (hash-chained), and return a `ToolResult`.

Any failure is **fail-safe**: no execution, an `ok=False` result, and an audit
record — and internal error text is never surfaced to the planner.

### 4. SSH executor (human-approved command execution)
- The model never gets a shell. It submits a **command intent**:
  `{host, command_template, params, reason, cve_ref}`.
- The executor:
  1. Resolves the command from an **allowlisted template catalog** (parameterized,
     not free-form string concatenation — prevents injection).
  2. Runs a **dry-run / plan** where the tooling supports it (e.g.
     `apt-get --simulate`, `dnf --assumeno`, config check modes).
  3. Presents the exact resolved command + dry-run output to a human for
     **approval**.
  4. On approval, executes over SSH using a key fetched from the vault, with a
     timeout, output size cap, and no interactive TTY.
  5. Captures stdout/stderr/exit code to the audit log.
- **Safeguards:**
  - Command **allowlist by default**; a denylist of destructive patterns
    (`rm -rf /`, `mkfs`, `dd of=/dev/...`, `:(){ :|:& };:`, disabling auditd/
    firewall, mass user deletion) that blocks even if an operator approves.
  - Per-host and per-fleet **rate limits** and **concurrency caps**.
  - **Canary rollout**: changes land on a small canary set first; the batch
    halts automatically if canaries fail health checks.
  - **Change windows**: writes only inside approved maintenance windows unless
    flagged an emergency (which requires a stronger approval).
  - Automatic **snapshot/backup** before mutating changes where the platform
    supports it, to enable rollback.

### 5. Authenticated scanner (read-only)
- A **read-only** detection component that logs into managed hosts (via the same
  vault-issued SSH credentials, resolved by the toolset — never by the model)
  and inspects local state to find missing patches and misconfigurations.
- Uses standard, auditable tooling: **OpenSCAP / OVAL** content, distro package
  managers in query mode (`apt list --upgradable`, `dnf updateinfo`,
  `rpm -qa`), and advisory OVAL definitions. Cloud-side, it reads provider patch
  and config state (e.g. SSM inventory, Azure Update Manager) through the
  read-only cloud adapter tools.
- **Strictly non-mutating.** It only runs query/check-mode commands drawn from
  the allowlist catalog's read-only subset; it cannot install, modify, or
  restart anything. Dry-run and write capabilities are *not* wired into this
  component — detection and remediation are separate code paths.
- Produces a per-host inventory of installed packages, versions, applied
  patches, and open misconfigurations. This feeds the remediation planner
  (below) so correlation is based on *actual observed host state*, not just
  registry metadata.
- Runs autonomously within policy and rate limits (it's read-only), on a
  schedule or on-demand after an advisory lands. Results are audit-logged.
- Separation of duties: the scanner **detects and reports**; it never decides or
  applies a fix. Any remediation it implies still goes through the planner and
  the human-approval gate.

### 6. Vulnerability intelligence & remediation planner
- Pulls from authoritative feeds: NVD/CVE, vendor advisories, OSV, distro
  security trackers, CISA KEV.
- Correlates disclosed vulns against the **authenticated scanner's observed
  host inventory** (and registry metadata) to produce an affected-host list,
  prioritized (KEV + CVSS +
  exposure + exploit availability).
- For each finding it builds a **remediation plan**:
  - **Patch available** → propose the vendor update via the patch tools.
  - **No patch yet** → propose the published **mitigation/workaround** from the
    advisory — clearly labeled as a temporary mitigation, with a tracking item
    to apply the real patch once released.
  - **Neither available** → raise for human decision; do not improvise.
- **Remediation is not only package installs.** Mitigation and hardening
  frequently means *changing system configuration*. Supported remediation action
  types:
  - **Config file edits** — e.g. `sshd_config`, `sysctl.conf`, TLS/cipher
    settings, auth/PAM config, application config.
  - **Kernel module changes** — blacklist/disable unused or insecure modules
    (e.g. `dccp`, `sctp`, `usb-storage`), or load a hardening module.
  - **Service state changes** — `disable`/`mask` an unneeded or vulnerable
    service; enable a protective one.
  - **Firewall rule edits** — tighten/harden by closing a port, restricting a
    source, or adding a CVE mitigation rule (distinct from *disabling* the
    firewall, which is blocked). WAF rules, access restrictions, feature
    disables.
  These go through **managed, idempotent primitives** (below), never free-form
  edits, and are subject to the same denylist, dry-run, approval, canary, and
  rollback rules as any other change.

### 6b. Remediation workflow (snapshot → patch → optional cleanup)
A patch remediation is sequenced so it is reversible by default:
- **Optional protective snapshot first** — the autonomous snapshot step runs
  before the change so a rollback point exists. It can be disabled per run.
- **If the snapshot was requested but fails, the patch is not attempted** — a
  host is never changed without a backup.
- **Snapshot taken once** — after the patch's approval, the workflow re-runs
  with the returned snapshot ids and skips re-snapshotting.
- **Retention** — the snapshot is kept through approval and through a failed
  patch (when it is most needed). Deleting it is a separate, deliberate,
  approval-gated **CLEANUP** action the operator invokes only once the fix is
  confirmed stable — a safety backup is never destroyed silently.

### 6a. Managed configuration primitives
Config/module/service remediations are expressed as declarative, reviewable
operations — not raw shell edits — so they can be validated, diffed, and rolled
back:
- **Config edits**: parameterized set-key/ensure-line/ensure-block operations
  against a known file, applied from templates. The executor **backs up the file,
  renders the change, shows the approver a diff, validates syntax** where a
  checker exists (`sshd -t`, `nginx -t`, `visudo -c`, `sysctl -p --dry-run`),
  and only then applies and reloads. Idempotent: re-running makes no further
  change.
- **Kernel modules**: managed via drop-ins (e.g. `/etc/modprobe.d/*.conf`
  blacklist/install lines) plus a runtime `modprobe -r`/`modprobe`, with the
  module name validated against an allowlisted set of hardening targets.
- **Services**: managed `systemctl enable/disable/mask/start/stop`, where the
  unit name is checked against the **denylist first** — security-critical units
  (`auditd`, `firewalld`, `ufw`, …) can never be disabled/masked, even with
  approval. Disabling a *vulnerable or unneeded* service is allowed; disabling a
  *protective* one is not.
- **Firewall rules**: managed via the firewall's own tooling
  (`firewalld`/`ufw`/`nft`), never raw packet-filter string edits. Editing rules
  to harden is allowed; *disabling* the firewall service is not (see protected
  services). Two extra safeguards apply to firewall/network changes: a **lockout
  guard** refuses any rule that would cut the harness's own SSH/management access,
  and a **timed auto-revert** applies the change, then rolls it back automatically
  unless a post-apply health check (management reachable, canaries healthy)
  confirms within the window — so a bad rule can't permanently sever access.
- Every such primitive records a **rollback action** (restore the backed-up
  file, re-enable the service, remove the blacklist drop-in, delete the firewall
  rule) in the audit log.
- Every proposed action cites its source advisory and is **verifiable by a human
  against the official advisory** before approval. The planner never invents a
  fix; if it can't cite a vendor/advisory source, it escalates instead.
- **Post-remediation verification**: re-scan to confirm the fix took, and record
  the before/after state.

### 7. Audit, logging & rollback
- Append-only, tamper-evident audit log of every intent, approval decision,
  executed command, and result. Secrets are redacted.
- Each change links back to its CVE/advisory, approver, and target set.
- Rollback procedures recorded alongside each change where feasible.

---

## Approval model (summary)

| Action class | Autonomy |
|---|---|
| Discovery / authenticated read-only scans | Allowed autonomously, within policy & rate limits |
| Protective (snapshot, backup) | Allowed autonomously before a gated change |
| Mitigation / patch on **canary** | Requires human approval |
| Mitigation / patch on **fleet** | Requires human approval (stronger, after canary passes) |
| Anything on denylist | Blocked unconditionally |
| Emergency change outside window | Requires elevated/second approval |

Approvals are per-change-set, logged, and expire if not acted on.

---

## Hard rules for anyone (human or model) working in this repo

1. **Only registered, authorized assets.** Never add capability to target
   arbitrary or third-party systems. This is not a scanning-the-internet tool.
2. **The model never receives secrets.** If a change would route a credential
   through a prompt, tool arg, or model-visible result, it's a bug — fix the
   boundary.
3. **No free-form remote command execution by the model.** All remote commands
   come from the reviewed, parameterized template catalog.
4. **Every remote-mutating action is human-approved** and audit-logged.
5. **Default deny.** New provider methods and new command templates are
   unreachable until explicitly wrapped, reviewed, and allowlisted.
6. **Cite the source.** Remediations must reference an official advisory/patch;
   no invented fixes.
7. **Fail safe.** On ambiguity, missing authorization, or policy conflict, stop
   and escalate to a human — never guess.

---

## Git / commit conventions

- **Do not include any Claude or AI attribution** in commits, PRs, tags, or
  changelog entries. No `Co-Authored-By: Claude`, no "Generated with Claude
  Code" footer, no AI-assistant trailers of any kind.
- Commit messages describe the change and reference the relevant CVE/advisory or
  ticket where applicable.
- Never commit secrets, private keys, `.env` files, vault tokens, or real host
  inventories. Keep an aggressive `.gitignore` and run secret-scanning in CI.
