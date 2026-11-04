# Connecting AI Defense to Claude (MCP)

The MCP server exposes a focused set of tools Claude can call in plain language:
`list_assets`, `scan`, `plan`, `upgrade_preflight` (read-only OS-upgrade
eligibility), `report` (write Markdown + DefectDojo/generic JSON to local files),
`remediate`, `mitigate` (apply a cited, reversible workaround), `list_mitigations`
(read-only: what `mitigate` can apply), `update_asset` (correct a host's
connection without re-onboarding), `approve_change`, `audit_tail`, plus the cloud
tools (below). Every call still goes through the dispatcher, so policy,
authorization, the approval gate, rate limits, redaction, and the audit log all
apply.

> Paths below assume this repo at `C:\path\to\ai_defense` and the
> `.venv` created by `install.ps1` / `install.sh`. Adjust if yours differ.

## 1. Pick a database (recommended)

Use a DB file so assets/approvals/audit persist and are shared between the chat
session and the operator terminal:

```
C:\path\to\ai_defense\ai.db
```

The server is launched with `--db sqlite+pysqlite:///C:/path/to/ai_defense/ai.db`.
Omit `--db` for an ephemeral in-memory run.

**Quick manual launch:** run `run-mcp.bat` (Windows) or `./run-mcp.sh`
(Linux/macOS) from the project folder — they cd in, use the venv's
`ai-defense`, and default the DB to `ai.db` beside the script. Pass a DB URL as
the first argument to override. (Claude launches the server itself via the
config below; these scripts are for trying it by hand.)

## 2a. Claude Desktop

Edit `claude_desktop_config.json`
(Windows: `%APPDATA%\Claude\claude_desktop_config.json`), add:

```json
{
  "mcpServers": {
    "ai-defense": {
      "command": "C:\\path\\to\\ai_defense\\.venv\\Scripts\\ai-defense.exe",
      "args": ["mcp",
               "--db", "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"]
    }
  }
}
```

Restart Claude Desktop. "ai-defense" should appear in the tools (plug) menu.

**Use the `ai-defense.exe` from the venv as the command** — it is self-contained
and avoids the most common failure, where `command` points at an interpreter
(plain `python`) that doesn't have the package installed, so the server crashes
at startup with `ModuleNotFoundError: No module named 'ai_defense'`. The
equivalent `"command": "...\\.venv\\Scripts\\python.exe", "args": ["-m",
"ai_defense", "mcp", ...]` also works, as long as it is the **venv** python.

### If it still says the server failed

- Check Claude Desktop's MCP logs: `%APPDATA%\Claude\logs\` (files named
  `mcp-server-ai-defense.log` / `mcp.log`). The startup traceback is there.
- Verify the command runs on its own (should print nothing and wait, Ctrl-C to
  stop — a traceback means a real error):
  `C:\path\to\ai_defense\.venv\Scripts\ai-defense.exe mcp`
- Make sure the JSON is valid (no trailing commas) and paths use `\\` or `/`.

## 2b. Claude Code (CLI)

**Add** the server (simulated backends, durable DB):

```bash
# bash / Linux / macOS
claude mcp add ai-defense -- \
  "C:/path/to/ai_defense/.venv/Scripts/ai-defense.exe" mcp \
  --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
```
```powershell
# PowerShell (Windows) — backtick continues lines
claude mcp add ai-defense -- `
  "C:\path\to\ai_defense\.venv\Scripts\ai-defense.exe" mcp `
  --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
```
```bat
:: cmd.exe (Windows) — one line
claude mcp add ai-defense -- "C:\path\to\ai_defense\.venv\Scripts\ai-defense.exe" mcp --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
```

**Real SSH mode** (patch actual hosts; needs the `ssh` extra and a key dir — see
"Real SSH mode" below):

```bash
# bash / Linux / macOS
claude mcp add ai-defense -- \
  "C:/path/to/ai_defense/.venv/Scripts/ai-defense.exe" mcp \
  --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" \
  --ssh-keys "C:/path/to/ai_defense/keys" \
  --known-hosts "C:/Users/you/.ssh/known_hosts"
```
```powershell
# PowerShell (Windows)
claude mcp add ai-defense -- `
  "C:\path\to\ai_defense\.venv\Scripts\ai-defense.exe" mcp `
  --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" `
  --ssh-keys "C:\path\to\ai_defense\keys" `
  --known-hosts "C:\Users\you\.ssh\known_hosts"
```
```bat
:: cmd.exe (Windows) — one line
claude mcp add ai-defense -- "C:\path\to\ai_defense\.venv\Scripts\ai-defense.exe" mcp --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --ssh-keys "C:\path\to\ai_defense\keys" --known-hosts "C:\Users\you\.ssh\known_hosts"
```

**Check / remove / re-add** (re-adding requires removing first — otherwise you
get `MCP server ai-defense already exists in local config`):

```bash
claude mcp list                 # should show: ai-defense ... - ✔ Connected
claude mcp get ai-defense       # show the stored command
claude mcp remove ai-defense    # remove it
```

To change the command (e.g. switch to real SSH mode), `remove` then `add` again.
Then `claude` — the tools are available in the session.

## 2c. Other MCP clients (opencode, Cursor, Cline, Zed, VS Code, …)

MCP is an open protocol and this is a standard **stdio** server, so any host that
can launch a local stdio MCP server can drive it — the planner/enforcer boundary
and every safeguard are identical regardless of client. Clients that work this
way include **opencode** (terminal agent — **verified with AI Defense**, see
below), **Cursor**, **Windsurf**, **Zed**, **VS Code** (Copilot agent mode), the
**Cline** and **Continue** extensions, **Goose**, **LibreChat**, desktop clients
like **Cherry Studio** / **5ire** / **Witsy**, and anything built on the MCP or
OpenAI Agents SDKs. Check each client's own MCP docs for where its config lives;
the block is almost always the same `mcpServers` shape as Claude Desktop (§2a):

```json
{
  "mcpServers": {
    "ai-defense": {
      "command": "C:\\path\\to\\ai_defense\\.venv\\Scripts\\ai-defense.exe",
      "args": ["mcp",
               "--db", "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"]
    }
  }
}
```

Add the same real-SSH / `--osv` / `--aws-region` args to `args` exactly as in
§2a/§2b. On macOS/Linux the command is `…/.venv/bin/ai-defense` (no `.exe`).

**opencode** (verified working) is the one exception to the `mcpServers` shape —
it uses its own `opencode.jsonc`, with the server under an `mcp` key and the
command as an **array** (append `--ssh-keys` / `--allow-unknown-hosts` / `--osv`
/ `--kev` / `--aws-region` to the array for real-SSH/cloud mode):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ai-defense": {
      "type": "local",
      "command": ["C:\\path\\to\\ai_defense\\.venv\\Scripts\\ai-defense.exe",
                  "mcp", "--db", "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"],
      "enabled": true
    }
  }
}
```

Put it in `./opencode.jsonc` (project-local) or `~/.config/opencode/opencode.jsonc`
(global). `opencode mcp list` prints the status (`✓ ai-defense connected`)
**without spending tokens** — a quick way to confirm the wiring before chatting.
Two caveats:

- **Local stdio only.** The host launches the server as a child process on the
  same machine; there is no network endpoint. A remote/hosted client (e.g.
  ChatGPT connectors, which expect an HTTP MCP endpoint) won't connect as-is —
  the `mcp` SDK *can* serve over HTTP/SSE, but exposing an infrastructure-control
  server on the network is a deliberate security step (auth, TLS, network ACLs),
  not the default posture.
- **The approval gate is server-side; the pre-run prompt is client-side.** The
  guarantees that matter hold with any client — secrets never reach the model,
  and a mutating tool returns *pending* until `approve_change` is called. But
  whether the client asks a human before each tool call varies, and some agent
  clients auto-run tools. Because `approve_change` is itself a tool, a fully
  auto-running agent could approve its own change-set — so with such a client,
  approve **out-of-band** (§5, the `pending` / `approve` CLI) to keep a human in
  the loop.

## 3. Onboard a host first

The demo backends ship a simulated vault key `ssh-key/vps-demo-01`, so onboard a
host that uses it (either ask Claude to, or out-of-band):

```bash
# bash
register-vps --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" \
  --asset-id vps-demo-01 --host 198.51.100.20 --key-ref ssh-key/vps-demo-01 \
  --owner you --environment prod --granted-by you --attestation-sig manual
```
```powershell
# PowerShell / cmd (Windows) — one line
register-vps --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --asset-id vps-demo-01 --host 198.51.100.20 --key-ref ssh-key/vps-demo-01 --owner you --environment prod --granted-by you --attestation-sig manual
```

## 4. Talk to Claude

Example prompts:

- "List the assets you can manage."
- "Scan vps-demo-01 and show me what's installed."
- "Plan remediations for vps-demo-01, highest priority first."
- "Patch openssl on vps-demo-01." → Claude calls `remediate`, which returns a
  **pending** change-set because it's a mutating action.

## 5. Approve mutating actions (human in the loop)

`remediate` returns `status: patch_pending` with a `change_set_id`. Approve it:

- In chat: "Approve change-set `cs_…`." (Claude calls `approve_change`), **or**
- Out-of-band in a terminal (recommended for real separation of duties):

```bash
# bash
ai-defense pending --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
ai-defense approve --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" \
  --change-set cs_... --approver you
```
```powershell
# PowerShell / cmd (Windows) — one line each
ai-defense pending --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
ai-defense approve --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --change-set cs_... --approver you
```

Then tell Claude "try the patch again" — `remediate` now applies it (dry-run
first) and returns `status: patched`. Ask "show me the audit log" to see the
hash-chained trail (`audit_tail`).

`remediate` fails safe on its negatives: if the advisory feed (OSV) is
temporarily throttled it returns `status: undetermined` ("retry shortly") rather
than a misleading `no_patch_available`, and an unreachable host returns
`status: scan_failed` — a transient data gap is never mistaken for "nothing to
patch". Likewise `plan` adds `feed_degraded: true` when its advisory fetch was
incomplete, so a thin plan isn't read as a clean bill of health.

Where a host **can't** take the vendor patch (e.g. an EOL OS without ESM), ask
Claude to *"mitigate CVE-2021-4034 on `<host>`"* — the `mitigate` tool applies the
cited, **reversible** workaround (for PwnKit, stripping the setuid bit from
`pkexec`), approval-gated and dry-run first, and records a rollback. Only CVEs
with a catalogued mitigation are eligible; anything else escalates to a human.

The catalogue is the built-ins **plus any files in a mitigations folder** you
point to with `--mitigations-dir` (yaml/json, one or many mitigations per file).
Each entry must reference a command already allowlisted in the reviewed catalog —
a file can map a CVE to an existing command, never add a new one. See
[`mitigations/README.md`](../mitigations/README.md) for the format.

```bat
ai-defense mcp --db "..." --ssh-keys "..." --osv --kev --mitigations-dir mitigations
```

## Safeguards that remain in force

- Claude only emits intents through these tools; it cannot run arbitrary
  commands or reach unregistered hosts.
- Mutating actions are **approval-gated** — a human authorizes each change-set,
  and the MCP client also prompts before any tool call runs.
- Credentials never pass through Claude; the SSH key is resolved from the vault
  by `key_ref` at execution time and redacted from results and the audit log.

## Real AWS mode (manage cloud from chat)

Add `--aws-region` to use **live boto3** for the cloud tools (install the extra:
`pip install -e ".[aws]"`). Authentication is by **CLI profile**: store a small
credential descriptor in the vault that the account's `credential_ref` points at,
e.g. a file `<keys>/aws/prod` containing `{"profile": "secops", "region": "us-east-1"}`
(or just the profile name). No AWS keys are stored by this tool.

```json
"args": ["mcp",
         "--db", "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db",
         "--ssh-keys", "C:\\path\\to\\ai_defense\\keys",
         "--aws-region", "us-east-1"]
```

Cloud tools exposed to chat: `onboard_cloud_account`, `cloud_regions` (EC2
enabled regions + Lightsail regions), `cloud_discover` (EC2 + Lightsail),
`cloud_patch_state` (SSM compliance), `cloud_remediate` (SSM patch baseline —
approval-gated). Flow: *"Onboard AWS account 123456789012 with
credential_ref aws/prod"* → approve → *"discover instances in 123456789012"* →
*"patch i-0abc… in that account"* → approve → done.

**Lightsail is region-scoped.** `cloud_discover` lists Lightsail across **all
regions** by default (it enumerates the Lightsail regions and queries each), and
each returned instance carries its `region`. EC2 in the same call is limited to
the server's `--aws-region`. So "list all my Lightsail instances regardless of
region" works out of the box; to pin Lightsail to one region, pass
`all_regions: false` to the `aws.lightsail.list_instances` tool.

## Live vulnerability data (OSV)

Add `--osv` so `plan` queries OSV.dev for the packages a scan observed, instead
of the built-in demo advisory set (uses stdlib HTTP, no extra install):

```json
"args": ["mcp", "--db", "...", "--ssh-keys", "...", "--osv", "--osv-ecosystem", "Debian"]
```

Set `--osv-ecosystem` to match your hosts (e.g. `Debian`, `Ubuntu`). Then
"scan + plan" reflects real CVEs with their fixed versions.

Add `--kev` to also fetch CISA's Known Exploited Vulnerabilities catalog and
sort actively-exploited CVEs to the top of the plan:

```json
"args": ["mcp", "--db", "...", "--osv", "--osv-ecosystem", "Debian", "--kev"]
```

In chat you can also say *"report web-prod-1"* to write the four report files
(executive summary, technical report, DefectDojo + generic JSON) to a local
folder, or *"preflight web-prod-1"* for a read-only OS-upgrade assessment.

## Reports from the CLI (and fleet sweep)

Reports can also be generated outside chat — handy for a terminal or a cron job.
The `report` command takes the same engine flags as `mcp`:

```bat
REM one or more named hosts
ai-defense report web-prod-1 --db "sqlite+pysqlite:///D:/.../ai.db" ^
  --ssh-keys "D:/.../keys" --allow-unknown-hosts --osv --kev

REM fleet-wide sweep: every registered ssh-host asset, into one combined report
ai-defense report --all --db "sqlite+pysqlite:///D:/.../ai.db" ^
  --ssh-keys "D:/.../keys" --allow-unknown-hosts --osv --kev
```

Output goes to `./reports/<timestamp>/` unless you pass `--out-dir`. `--all`
selects every registered `ssh-host` asset (cloud-account and control-plane
assets are not SSH-scannable), so onboard your hosts first (and point `--db` at
the database they were onboarded into). Reports are written locally only.

Two fail-safes make a report honest about what it couldn't see. A host that
could **not** be scanned is listed with a type-based, actionable reason
(`TimeoutError` → unreachable on :22, check the firewall; `AuthenticationException`
→ verify user/key_ref; `BadHostKeyException` → host rebuilt, clear the stale
`known_hosts` entry). And if the advisory feed (OSV) was unreachable or
rate-limited mid-sweep, the fetch is **incomplete** — so every artifact carries a
`feed_degraded` flag and a loud banner, and the DefectDojo file tags findings
`scan-degraded` (import it with auto-close disabled). A degraded or partial scan
is never presented as a clean bill of health.

If a host is **intentionally** not SSH-reachable (off-limits by design), mark it
exempt so it is skipped and reported as *exempt* rather than counted as a
failure:

```bat
ai-defense scan-exempt --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --asset-id web-01 --reason "no SSH by design"
```

Clear it with `--clear`. The flag is a non-secret registry attribute (connection
and authorization untouched); exempt hosts are skipped by `report` / `report
--all` and listed under their own "exempt" line, distinct from real scan
failures.

## Bulk onboarding (fill the fleet from cloud discovery)

`report --all` only covers hosts that are **registered**. To turn your
discovered cloud instances into `ssh-host` assets in one shot, use
`bulk-onboard` (an operator / out-of-band action — you supply the authorization
attestation, exactly like `register-vps`, just many hosts at once). The SSH
keys must already be in the vault; only a `key_ref` is stored, never a key.

```bat
REM 1. preview from a saved cloud_discover output (no DB needed for --dry-run)
ai-defense bulk-onboard --from-json discovered.json --dry-run ^
  --owner secops --granted-by clint --attestation-sig "ticket-4821" ^
  --key-ref "ssh-key/lightsail-default"

REM 2. discover live from a registered account, then write to the DB
ai-defense bulk-onboard --account 123456789012 --aws-region us-east-1 ^
  --db "sqlite+pysqlite:///D:/.../ai.db" ^
  --owner secops --granted-by clint --attestation-sig "ticket-4821" ^
  --key-ref "ssh-key/lightsail-default"
```

- Input is either `--from-json FILE` (a `cloud_discover` result — `{"instances":[…]}`
  or a bare list) or `--account ID` for live discovery (EC2 + Lightsail).
- The **SSH user is inferred** from each instance's platform/blueprint
  (`ubuntu_*`→`ubuntu`, `debian_*`→`admin`, `amazon_*`→`ec2-user`,
  WordPress/LAMP/Bitnami→`bitnami`, …); override with `--user`.
- **One key for all** via `--key-ref`, or **per-host** via `--key-ref-map FILE`
  (`{"asset-id": "ssh-key/ref"}`). A host with no key reference, or no reachable
  address, is **skipped** and listed — never guessed around.
- `--environment` tags all hosts (otherwise each instance's `env` tag, else
  `unknown`). `--dry-run` previews; without it (and with `--db`) the signed
  registrations are persisted. Afterwards, `report --all` covers the fleet.

## Correcting a registered host (`update-asset`)

Connection details drift: a key is rotated, a rebuilt host changes address or
host key, or a login was onboarded wrong. Fix just the connection **without
re-onboarding** — the authorization/attestation is preserved (unlike
re-registering, which re-signs it).

- **In chat:** *"Update web-01 to use key `ssh-key/web-01-new`"* → Claude calls
  `update_asset`, which returns a **pending** change-set until you approve
  (exactly like `remediate`), then applies it.
- **Operator CLI** (out-of-band, immediate):

```bat
:: cmd.exe (Windows) — one line
ai-defense update-asset --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --asset-id web-01 --key-ref ssh-key/web-01-new
```

Change any of `--host` / `--port` / `--user` / `--key-ref` (only what you pass is
touched). A new `key_ref` must already resolve in the vault — the key value is
never handled. Identity fields (owner/environment) and the attestation are
deliberately **not** updatable this way; changing those is a re-onboarding.

## Real SSH mode (patch actual hosts)

By default the server uses **simulated** backends (nothing touches real hosts).
To act on real machines over SSH, add `--ssh-keys` pointing at a key directory
(install the extra first: `pip install -e ".[ssh]"`):

```json
{
  "mcpServers": {
    "ai-defense": {
      "command": "C:\\path\\to\\ai_defense\\.venv\\Scripts\\ai-defense.exe",
      "args": ["mcp",
               "--db", "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db",
               "--ssh-keys", "C:\\path\\to\\ai_defense\\keys",
               "--known-hosts", "C:\\Users\\you\\.ssh\\known_hosts"]
    }
  }
}
```

- **Where to keep keys:** the `--ssh-keys` directory can live anywhere the
  server can read; treat it as a credential store. Preferred: a user-private
  location outside the repo — `C:\Users\you\.ai-defense\keys` (Windows) or
  `~/.ai-defense/keys` (Linux/macOS) — locked down (`chmod 700`, or on Windows
  `icacls <dir> /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"`). A project-local
  `keys/` works too and is git-ignored, but outside the repo is safer. The DB
  only ever stores the `key_ref`, never the key.
- Put each private key at `<keys>/<key_ref>` — e.g. `key_ref` `ssh-key/vps-01`
  → file `<keys>/ssh-key/vps-01`.
- Keys are OpenSSH/PEM. A PuTTY `.ppk` is accepted too: **unencrypted** `.ppk`
  files (ed25519 / RSA / ECDSA) are parsed natively — just drop the `.ppk` at
  `<keys>/ssh-key/<name>`, no conversion needed. An **encrypted** `.ppk` falls
  back to a CLI `puttygen` if on PATH (Linux/WSL); on Windows the GUI puttygen
  can't convert headless, so export an OpenSSH key once from the PuTTYgen GUI
  (Conversions → Export OpenSSH key) or remove the passphrase.
- Host-key verification is **on**: the target must be in `--known-hosts`. Add
  `--allow-unknown-hosts` only for trust-on-first-use (less safe).
- Cloud (AWS) tools remain simulated in this mode; a live AWS backend is a
  separate step.

Then onboard a host whose `key_ref` matches a key file, and `scan` / `remediate`
run real `dpkg-query` / `apt-get` over SSH (dry-run first, approval-gated).
