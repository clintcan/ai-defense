"""LLM-facing planning layer.

The planner turns goals ("remediate CVE-2026-1234 across web-prod") into
`Intent` objects. It NEVER receives secrets, NEVER runs commands, and only sees
redacted `ToolResult`s. This is the single trust boundary with the model.
"""
