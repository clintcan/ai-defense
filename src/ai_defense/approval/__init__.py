"""Human approval gate (CLAUDE.md approval model).

Every remote-mutating action is approved per change-set: canary first, then
fleet (stronger). Emergency changes outside the window need elevated/second
approval. Approvals are logged and expire if not acted on.
"""
