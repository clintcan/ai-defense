"""SSH executor (CLAUDE.md component 4). Human-approved command execution.

The model never gets a shell. It submits a command *intent*; the executor
resolves it from a parameterized allowlist catalog, dry-runs it, requires human
approval, then runs it with a vault-issued key — no interactive TTY, with
timeout and output caps. A destructive-pattern denylist blocks even approved
commands.
"""
