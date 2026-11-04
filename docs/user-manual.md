# AI Defense — User Manual

A plain-language guide to installing AI Defense and using it from Claude. No
programming needed — if you can open a terminal and copy-paste, you can set this
up.

> **What you'll end up with:** you chat with Claude in plain English ("scan my
> servers", "what needs patching?", "write me a report"), and AI Defense does
> the work safely in the background — never changing a server without your
> explicit approval.

---

## Contents

1. [What AI Defense is (and isn't)](#1-what-ai-defense-is-and-isnt)
2. [How it keeps you safe](#2-how-it-keeps-you-safe)
3. [Before you start](#3-before-you-start-checklist)
4. [Step 1 — Install it](#4-step-1--install-it)
5. [Step 2 — Choose where your data is stored](#5-step-2--choose-where-your-data-is-stored)
6. [Step 3 — Put your server keys in a folder](#6-step-3--put-your-server-keys-in-a-folder-real-servers-only)
7. [Step 4 — Connect it to Claude](#7-step-4--connect-it-to-claude)
8. [Step 5 — Tell it about your servers](#8-step-5--tell-it-about-your-servers-onboarding)
9. [Step 6 — Everyday use](#9-step-6--everyday-use)
10. [Step 7 — Approving changes](#10-step-7--approving-changes)
11. [Fixing a server's details later](#11-fixing-a-servers-details-later)
12. [Understanding the reports](#12-understanding-the-reports)
13. [Troubleshooting](#13-troubleshooting)
14. [Glossary](#14-glossary)
15. [Where to find more detail](#15-where-to-find-more-detail)

---

## 1. What AI Defense is (and isn't)

AI Defense helps you **keep the servers you own up to date and secure**. It:

- builds an inventory of your machines,
- logs in (read-only) to see what software is installed,
- checks that software against public lists of known vulnerabilities, and
- proposes fixes — which **only happen after you approve them**.

**It is not** a tool for scanning the internet or other people's systems. It
only ever touches machines **you have registered and attested that you're
allowed to manage**. Pointing it at anything else is blocked by design.

---

## 2. How it keeps you safe

Think of it as three roles that never blur together:

```
  You  ─talk to→  Claude (the planner)  ─proposes→  Toolset (the enforcer)  ─acts on→  Your servers
                   never sees passwords                checks the rules,
                   never runs commands directly        asks you to approve,
                                                        then does the work
```

Three promises the software enforces in code, not just policy:

1. **Claude never sees your passwords or keys.** They're kept in a separate
   "vault" and only used at the last moment, then wiped from anything Claude can
   read.
2. **Nothing that changes a server happens without your approval.** Reading and
   scanning is automatic; patching, config changes, anything that *modifies* a
   machine waits for a human "yes".
3. **Everything is logged** in a tamper-evident history, each change linked to
   the vulnerability it fixes and the person who approved it.

You don't have to configure any of that — it's always on.

---

## 3. Before you start (checklist)

You'll need:

- [ ] **A computer** running Windows, macOS, or Linux.
- [ ] **Python 3.11 or newer.** To check, open a terminal and run `python
      --version` (on some systems `python3 --version`). If it's missing or
      older, install it from [python.org](https://www.python.org/downloads/).
- [ ] **Claude** — either the **Claude Desktop** app or **Claude Code** (the
      command-line version). Either works.
- [ ] *(Only if you'll manage real servers over SSH)* the **SSH key files** for
      those servers, and their addresses.
- [ ] *(Only if you'll manage AWS cloud servers)* the **AWS CLI** set up with a
      profile, as you'd use it normally.

> **New to this?** You can try everything first in **demo mode**, which uses
> pretend servers and touches nothing real. Just skip the key/AWS items above.

Throughout this manual we assume the software lives at
`C:\path\to\ai_defense`. If yours is somewhere else, substitute your
own path everywhere you see that.

---

## 4. Step 1 — Install it

The easiest way is the one-shot installer. It creates a private workspace
(called `.venv`), installs everything, and runs a quick self-test.

**Windows (PowerShell)** — open the project folder and run:

```powershell
.\install.ps1 -Extras "mcp,ssh,aws"
```

**macOS / Linux**:

```bash
./install.sh mcp,ssh,aws
```

The `mcp,ssh,aws` part adds three optional pieces:

| Piece | Add it if you want to… |
|-------|------------------------|
| `mcp` | talk to it through Claude (almost everyone wants this) |
| `ssh` | manage **real servers** over SSH |
| `aws` | manage **AWS cloud** servers |

Leave out the ones you don't need (e.g. `.\install.ps1 -Extras "mcp"` for a
chat-only demo). You can re-run the installer later to add more.

**How to know it worked:** the installer finishes by running the test suite and
a demo. You should see tests passing and a short walkthrough printed. If you see
errors about Python version, revisit the [checklist](#3-before-you-start-checklist).

---

## 5. Step 2 — Choose where your data is stored

AI Defense remembers your servers, approvals, and history in a single database
**file**. Pick a location — a file named `ai.db` inside the project folder is a
fine default:

```
C:\path\to\ai_defense\ai.db
```

You don't create this file yourself; it's made automatically the first time it's
used. You just decide the path, because you'll refer to it in the next step. In
commands it's written as a "database URL" that looks like this (note the forward
slashes):

```
sqlite+pysqlite:///C:/path/to/ai_defense/ai.db
```

> **Why a file?** So the chat session and your terminal share the same memory —
> you can approve a change in a terminal while chatting with Claude, and
> everything survives a restart.

---

## 6. Step 3 — Put your server keys in a folder (real servers only)

*Skip this section if you're only trying the demo or only managing AWS.*

To log into real servers, AI Defense needs their SSH keys — but it keeps them in
a **key folder** that acts as the vault. The database only ever stores a short
*name* for each key (a "key reference"), never the key itself.

1. **Make a key folder.** Keeping it outside the project, in your user account,
   is safest:
   - Windows: `C:\Users\you\.ai-defense\keys`
   - macOS / Linux: `~/.ai-defense/keys`

2. **Put each private key in it**, at a path that matches the name you'll give
   it. If you plan to call a key `ssh-key/web-01`, the file goes at
   `…\keys\ssh-key\web-01`.

3. **Key formats:** standard OpenSSH/PEM keys work. **Unencrypted** PuTTY `.ppk`
   files work directly too — just drop them in. (An encrypted `.ppk` needs to be
   exported to OpenSSH format first, or have its passphrase removed.)

> **Keep this folder private.** Treat it like a drawer of house keys. On Windows,
> right-click → Properties → Security to restrict it to your account; on
> macOS/Linux run `chmod 700` on the folder.

---

## 7. Step 4 — Connect it to Claude

Pick the one that matches how you use Claude.

### 7a. Claude Desktop (the app)

1. Open the config file (create it if it's not there):
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
2. Paste this (adjust the path to your install), then save:

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

3. **Restart Claude Desktop.** "ai-defense" should appear in the tools (🔌)
   menu.

> On macOS/Linux the `command` is `…/.venv/bin/ai-defense` (no `.exe`).

### 7b. Claude Code (the command-line version)

Run this once (adjust the path). It's one line:

```
claude mcp add ai-defense -- "C:\path\to\ai_defense\.venv\Scripts\ai-defense.exe" mcp --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
```

Then `claude mcp list` should show **ai-defense … ✔ Connected**.

### Turning on the real-server and cloud features

The command above runs in safe **demo mode**. To manage real machines, add more
options after `mcp`:

| Add this | To… |
|----------|-----|
| `--ssh-keys "C:\Users\you\.ai-defense\keys"` | use your real SSH key folder (Step 3) |
| `--osv --kev` | check against live vulnerability data + "actively exploited" alerts |
| `--aws-region us-east-1` | manage AWS cloud servers |
| `--known-hosts "C:\Users\you\.ssh\known_hosts"` | verify server identities (recommended) |

A full real-server line looks like:

```
claude mcp add ai-defense -- "C:\path\to\ai_defense\.venv\Scripts\ai-defense.exe" mcp --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --ssh-keys "C:\Users\you\.ai-defense\keys" --osv --kev
```

> **Important:** always use the `ai-defense.exe` **from the `.venv` folder** as
> the command (as shown). Pointing at a plain `python` is the most common cause
> of "the server failed to start".
>
> To change the options later in Claude Code: `claude mcp remove ai-defense`,
> then add it again with the new line.

---

## 8. Step 5 — Tell it about your servers (onboarding)

AI Defense will only act on servers you've **registered** (called *onboarding*).
This is the deliberate "I'm authorized to manage this" step. Three ways:

### Option A — Ask Claude (one server, with your approval)

Just say: *"Onboard my server at 198.51.100.20, key `ssh-key/web-01`, owner me,
environment prod."* Claude proposes it; you approve; it's registered.

### Option B — Register one server yourself (a terminal command)

```
register-vps --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --asset-id web-01 --host 198.51.100.20 --key-ref ssh-key/web-01 --owner you --environment prod --granted-by you --attestation-sig "ticket-123"
```

- `--asset-id` is the short name you'll use for it ("web-01").
- `--key-ref` must match a key file from Step 3.
- `--attestation-sig` is your note of authorization (e.g. a ticket number).

### Option C — Register many at once from the cloud (fleet)

If your servers are in AWS, AI Defense can discover them and register them in one
pass. Preview first with `--dry-run` (writes nothing):

```
ai-defense bulk-onboard --account 123456789012 --aws-region us-east-1 --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --owner secops --granted-by you --attestation-sig "ticket-123" --key-ref "ssh-key/lightsail-default" --dry-run
```

It figures out the right login name for each machine automatically, and
**skips** (never guesses at) any server missing a key or an address. Remove
`--dry-run` to actually register them. Use `--key-ref-map` if different servers
use different keys.

---

## 9. Step 6 — Everyday use

Once servers are onboarded, just talk to Claude. Useful things to say:

| Say this | What happens |
|----------|--------------|
| "List the servers you can manage." | Shows your inventory. |
| "Scan web-01." | Reads what's installed (read-only, automatic). |
| "What needs patching on web-01, most urgent first?" | A prioritized plan — actively-exploited issues at the top. |
| "Write me a report for all my servers." | Produces the four report files ([explained below](#12-understanding-the-reports)). |
| "Is web-01 due for an OS upgrade?" | A read-only "preflight" assessment. |
| "Patch openssl on web-01." | Proposes the fix and **waits for your approval**. |

Nothing in the first five rows changes anything — they're safe to run anytime.
Only the last row (patching) needs approval, covered next.

---

## 10. Step 7 — Approving changes

When you ask for a change (a patch, a config fix), Claude comes back with
something like *"this is pending approval, change-set `cs_1a2b…`"*. Nothing has
happened to the server yet. To approve:

- **In chat:** say *"Approve change-set `cs_1a2b…`."*, **or**
- **In a terminal** (good when a different person should approve):

```
ai-defense pending --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db"
ai-defense approve --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --change-set cs_1a2b... --approver you
```

Then tell Claude *"try it again"* and the change goes through — always doing a
practice ("dry") run first, and recording the result in the history. You can
always say *"show me the audit log"* to see what happened.

---

## 11. Fixing a server's details later

Servers change — a key gets rotated, a machine is rebuilt with a new address, or
you onboarded it with the wrong login. You can correct a server's connection
details **without re-registering it** (its authorization stays intact):

- **Ask Claude:** *"Update web-01 to use key `ssh-key/web-01-new`."* It proposes
  the change and waits for your approval, like any other change.
- **Or in a terminal:**

```
ai-defense update-asset --db "sqlite+pysqlite:///C:/path/to/ai_defense/ai.db" --asset-id web-01 --key-ref ssh-key/web-01-new
```

You can change any of `--host`, `--port`, `--user`, `--key-ref`. A new key must
already be in your key folder (Step 3).

---

## 12. Understanding the reports

Asking for a report writes **four files** into a local folder (nothing is ever
uploaded — a list of your weak spots is exactly what shouldn't leave your
network):

| File | Who it's for | What's in it |
|------|--------------|--------------|
| `executive-summary.md` | managers / decision-makers | Plain-language posture: how many urgent issues, how many servers need an OS upgrade, top risks, recommended actions. |
| `technical-report.md` | whoever does the fixing | Per-server detail, each finding with a link to the official advisory so a human can verify it. |
| `findings.generic.json` | other tools / records | A structured, documented data file. |
| `findings.defectdojo.json` | vulnerability-tracking software | Ready to import into [DefectDojo](https://www.defectdojo.org/). |

If a scan couldn't reach some servers, the report **says so prominently** rather
than pretending everything is clean.

---

## 13. Troubleshooting

**"The server failed to start" (in Claude).**
Almost always the `command` isn't pointing at the `.venv` copy of
`ai-defense`. Use the full path to `…\.venv\Scripts\ai-defense.exe` (Step 4).
Claude Desktop keeps logs in `%APPDATA%\Claude\logs\` if you need the details.

**A report says a server "could not be scanned".**
The report now tells you *why* in plain terms. The common ones:

| Message says… | It means… | Fix |
|---------------|-----------|-----|
| *unreachable on the SSH port — check the firewall* | the server didn't answer on port 22 | open port 22 to your machine in the server's firewall (e.g. the cloud "Networking" tab) |
| *SSH authentication rejected — verify user and key_ref* | wrong login name or key | correct it with [update-asset](#11-fixing-a-servers-details-later) |
| *host key changed (likely rebuilt) — clear the stale known_hosts entry* | the server was rebuilt and now looks "different" | remove its old line from your `known_hosts` file (your terminal's `ssh-keygen -R <address>` does this), then scan again |

**"Authorization invalid/expired."**
A server's authorization has a time limit. Re-onboard it (Step 5) to renew.

**It won't touch a server at all.**
By design — the server must be **onboarded** first (Step 5), and changes need
**approval** (Step 7). This is the safety model working, not a bug.

If you're stuck, run the connection by hand to see the real error:
`C:\path\to\ai_defense\.venv\Scripts\ai-defense.exe mcp` (it should
just wait quietly; press Ctrl-C to stop — a wall of red text means a real
problem to read).

---

## 14. Glossary

- **Asset** — a server (or cloud account) you've registered.
- **Onboarding** — registering an asset and attesting you're allowed to manage
  it. The deliberate "trust" step.
- **Vault / key folder** — where SSH keys and passwords live, separate from
  everything Claude can see.
- **key_ref** — the short *name* of a key (e.g. `ssh-key/web-01`); the real key
  file sits in your key folder under that name.
- **Change-set** — one proposed change, identified by an id like `cs_1a2b…`,
  waiting for your approval.
- **KEV** — "Known Exploited Vulnerabilities", a public list of flaws criminals
  are *actively* using. AI Defense pushes these to the top.
- **EOL / ESM** — an operating system that's "End Of Life" (no more security
  fixes) or on "Extended Security Maintenance". These usually need an OS upgrade,
  not just a patch.
- **Preflight** — a read-only check of whether a server is ready for an OS
  upgrade. It only advises; it never upgrades anything.
- **Audit log** — the tamper-evident history of everything that was proposed,
  approved, and done.

---

## 15. Where to find more detail

- **[README.md](../README.md)** — a feature overview and quick start.
- **[docs/connect-claude.md](./connect-claude.md)** — the full, detailed guide to
  connecting Claude (every option, cloud/AWS mode, bulk onboarding).
- **[CLAUDE.md](../CLAUDE.md)** — the complete architecture and security model,
  for the technically curious.

You can also simply **ask Claude** how to do something once it's connected —
"how do I onboard a server?" — and it will walk you through it.
