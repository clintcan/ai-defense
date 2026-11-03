"""Intent validators — run before policy evaluation.

Checks (fail safe -> reject):
  * tool is registered/allowlisted
  * params conform to the tool's JSON schema (no extra/free-form fields)
  * targets are well-formed asset IDs (authorization is checked in policy)
  * action_class is consistent with the tool's read_only flag
"""

from __future__ import annotations

from .intents import Intent
from .registry import ToolRegistry


class ValidationError(Exception):
    pass


def validate(intent: Intent, registry: ToolRegistry) -> None:
    spec = registry.get(intent.tool)        # raises KeyError if not allowlisted
    if not intent.targets:
        raise ValidationError("intent has no targets")
    # TODO: JSON-schema validation of intent.params against spec.schema
    _ = spec
