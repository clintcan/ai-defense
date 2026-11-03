"""AI Defense — defensive orchestration & remediation harness.

Package layout mirrors the components in CLAUDE.md. The governing rule:
the LLM is a *planner*, never an *actor*. The ``planner`` package is the only
LLM-facing surface; everything a change actually touches lives behind the
``toolset`` enforcement layer, which resolves secrets and executes actions.
"""

__version__ = "0.0.1"
