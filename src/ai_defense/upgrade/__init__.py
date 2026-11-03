"""OS-upgrade intelligence.

Read-only preflight assessment of whether a host can be moved to a supported OS
release, and what the supported path is. This is the first, non-mutating slice of
the larger (future) ``OS_UPGRADE`` workflow — it detects and reports, it never
changes anything (CLAUDE.md components 5/6; see 6c).
"""
