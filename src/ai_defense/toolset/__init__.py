"""Toolset enforcement layer — the non-LLM core (CLAUDE.md "Core security model").

Everything a change actually touches lives here: policy engine, intent
validators, the tool registry (the only surface the planner reaches), and the
dispatch pipeline that resolves secrets and executes. The planner proposes;
this layer decides and acts.
"""
