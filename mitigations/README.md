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
reviewed catalog (`src/ai_defense/ssh/catalog/`). It can **not** introduce a
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

## Samples in this folder

| file | mitigation | command (allowlisted) |
|------|------------|------------------------|
| `pwnkit.yaml` | CVE-2021-4034 (PwnKit): strip setuid from `pkexec` | command `harden.disable_pkexec_suid` |
| `tcp-sack-panic.yaml` | CVE-2019-11477/11478/11479 (SACK Panic): disable TCP SACK | command `harden.disable_tcp_sack` |
| `mptcp.yaml` | Disable Multipath TCP persistently | config drop-in `config.sysctl_mptcp_off` |
| `sshd-x11.yaml` | sshd: disable X11 forwarding (no conf.d) | in-place block edit `config.sshd_disable_x11` |
| `http2-rapid-reset.yaml` | CVE-2023-44487 (HTTP/2 Rapid Reset): cap nginx concurrent streams | config drop-in `config.nginx_http2_rapidreset` |
| `php-session-upload-progress.yaml` | Disable PHP `session.upload_progress` on Ubuntu-packaged PHP-FPM (LFI→RCE hardening) | config drop-in `config.php_disable_upload_progress` |
| `php-session-upload-progress-bitnami.yaml` | Same, for Bitnami LAMP (bundled PHP, Apache mod_php) | config drop-in `config.php_disable_upload_progress_bitnami` |
| `kernel-module-dccp.yaml` | CVE-2017-6074 (DCCP use-after-free LPE): blacklist the `dccp` module | kernel-module `module.blacklist_dccp` |
| `service-rpcbind.yaml` | CVE-2017-8779 (rpcbomb DoS): disable `rpcbind` where unneeded | service `service.disable_rpcbind` |
| `firewall-memcached.yaml` | CVE-2018-1000115 (memcached UDP amplification): block UDP 11211 | firewall `firewall.deny_udp_memcached` |

A `template`/`rollback_template` may name any reviewed catalog action:

- a **command** — a fixed argv in `ssh/catalog/` (packages, sysctl/chmod hardening);
- a **config action** (`ssh/catalog/configs.py`) — a managed drop-in or in-place
  marker-block edit under an allowlisted path, with an optional validator (e.g.
  `nginx -t`), reloaded, and rolled back if validation fails;
- a **kernel-module action** (`ssh/catalog/modules.py`) — blacklist/unblacklist a
  module whose name is on the hardening allowlist (`/etc/modprobe.d` drop-in +
  `modprobe -r`);
- a **service action** (`ssh/catalog/services.py`) — `systemctl disable/mask/enable`,
  denylist-first so a protected unit (auditd, firewalld, ufw, sshd, …) can never be
  disabled;
- a **firewall action** (`ssh/catalog/firewall.py`) — a `ufw` rule edit with a
  lockout guard (never cut management SSH) and a timed auto-revert that rolls the
  rule back unless a post-apply health check confirms the host is still reachable.

Either way it must already be reviewed in the catalog — a file can map a CVE to an
existing action but can never introduce a new one.

To undo an applied mitigation, use the `revert_mitigation` tool (it runs the
entry's `rollback_template`) — a separate, approval-gated change, not a re-run of
`mitigate`.

Each is a single-mitigation file; put several in one file as a YAML/JSON list if
you prefer. All are runtime changes (reversible); persist a sysctl one across
reboot with a drop-in in `/etc/sysctl.d`.
