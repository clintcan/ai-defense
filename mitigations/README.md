# Mitigations folder

Drop files here to extend the catalogue of **published CVE mitigations** — the
reversible workarounds `ai-defense` applies (via the approval-gated `mitigate`
tool) when a host can't take the vendor patch (e.g. an EOL OS without ESM).

Load the folder by pointing any engine command at it:

```
ai-defense mcp    --mitigations-dir mitigations  ...
ai-defense report --mitigations-dir mitigations  ...
```

Entries here are **merged with the built-ins**; an entry whose `id` matches a
built-in overrides it (handy to retune a citation or command mapping without
editing code).

## The one hard rule

A mitigation file maps a CVE to a command that is **already allowlisted** in the
reviewed catalog (`src/ai_defense/ssh/catalog.py`). It can **not** introduce a
new command. The loader **rejects** (skips, with a warning) any entry whose
`template`/`rollback_template` isn't in the catalog. This keeps the "no free-form
remote execution / default-deny on new commands" guarantee (CLAUDE.md #3/#5):
curating *which* CVE gets *which reviewed command* is data; adding a genuinely
new command is a reviewed code change to the catalog.

## File format (`.yaml`, `.yml`, or `.json`)

A file may contain **one** mitigation (a mapping), a **list** of them, or a
mapping with a top-level `mitigations:` list. Fields:

| field | required | meaning |
|-------|----------|---------|
| `id` (or `mitigation_id`) | yes | unique id; matches an allowlisted command mapping |
| `cve` / `cves` | yes | one CVE string or a list |
| `title` | yes | human summary of the workaround |
| `source_ref` (or `source`) | yes | advisory URL a human can verify (rule #6) |
| `template` | yes | allowlisted catalog command that **applies** it |
| `rollback_template` (or `rollback`) | yes | allowlisted catalog command that **reverses** it |
| `description` | no | short note shown in the rollback record |
| `temporary` | no | default `true` (a mitigation is a stopgap until the patch) |

See `pwnkit.yaml` for a complete example.
