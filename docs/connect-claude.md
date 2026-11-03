# Connecting AI Defense to Claude (MCP)

The MCP server exposes six tools — `list_assets`, `scan`, `plan`, `remediate`,
`approve_change`, `audit_tail` — that Claude can call in plain language. Every
call still goes through the dispatcher, so policy, authorization, the approval
gate, rate limits, redaction, and the audit log all apply.

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
claude mcp add ai-defense -- \
  "C:/path/to/ai_defense/.venv/Scripts/ai-defense.exe" mcp \
  --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
```

**Real SSH mode** (patch actual hosts; needs the `ssh` extra and a key dir — see
"Real SSH mode" below):

```bash
claude mcp add ai-defense -- \
  "C:/path/to/ai_defense/.venv/Scripts/ai-defense.exe" mcp \
  --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" \
  --ssh-keys "C:/path/to/ai_defense/keys" \
  --known-hosts "C:/Users/you/.ssh/known_hosts"
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

## 3. Onboard a host first

The demo backends ship a simulated vault key `ssh-key/vps-demo-01`, so onboard a
host that uses it (either ask Claude to, or out-of-band):

```bash
register-vps --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" \
  --asset-id vps-demo-01 --host 198.51.100.20 --key-ref ssh-key/vps-demo-01 \
  --owner you --environment prod --granted-by you --attestation-sig manual
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
ai-defense pending --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
ai-defense approve --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" \
  --change-set cs_... --approver you
```

Then tell Claude "try the patch again" — `remediate` now applies it (dry-run
first) and returns `status: patched`. Ask "show me the audit log" to see the
hash-chained trail (`audit_tail`).

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

Cloud tools exposed to chat: `onboard_cloud_account`, `cloud_discover` (EC2 +
Lightsail), `cloud_patch_state` (SSM compliance), `cloud_remediate` (SSM patch
baseline — approval-gated). Flow: *"Onboard AWS account 123456789012 with
credential_ref aws/prod"* → approve → *"discover instances in 123456789012"* →
*"patch i-0abc… in that account"* → approve → done.

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

- Put each private key at `<keys>/<key_ref>` — e.g. `key_ref` `ssh-key/vps-01`
  → file `<keys>/ssh-key/vps-01`. Keep that directory owner-only and out of git.
- Keys are OpenSSH/PEM. A PuTTY `.ppk` is accepted too and auto-converted **if
  `puttygen` is on PATH** (install PuTTY). Without `puttygen`, convert once:
  `puttygen mykey.ppk -O private-openssh -o <keys>/ssh-key/vps-01`. For an
  encrypted `.ppk`, pass its passphrase to `ParamikoTransport(key_passphrase=...)`.
- Host-key verification is **on**: the target must be in `--known-hosts`. Add
  `--allow-unknown-hosts` only for trust-on-first-use (less safe).
- Cloud (AWS) tools remain simulated in this mode; a live AWS backend is a
  separate step.

Then onboard a host whose `key_ref` matches a key file, and `scan` / `remediate`
run real `dpkg-query` / `apt-get` over SSH (dry-run first, approval-gated).
