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

## 2a. Claude Desktop

Edit `claude_desktop_config.json`
(Windows: `%APPDATA%\Claude\claude_desktop_config.json`), add:

```json
{
  "mcpServers": {
    "ai-defense": {
      "command": "C:\\path\\to\\ai_defense\\.venv\\Scripts\\python.exe",
      "args": ["-m", "ai_defense", "mcp",
               "--db", "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"]
    }
  }
}
```

Restart Claude Desktop. "ai-defense" should appear in the tools (plug) menu.

## 2b. Claude Code (CLI)

```bash
claude mcp add ai-defense -- \
  "C:/path/to/ai_defense/.venv/Scripts/python.exe" -m ai_defense mcp \
  --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
```

Then `claude` — the tools are available in the session. (`claude mcp list` to
check, `claude mcp remove ai-defense` to undo.)

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

## Note on backends

This server runs on **simulated** vault/SSH/AWS backends (nothing touches real
hosts yet). It's safe to explore end to end. Real backends (paramiko SSH, live
boto3, a real vault) are injected via `composition.build_engine(...)` and are
the next build step.
