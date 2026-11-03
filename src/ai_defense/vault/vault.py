"""Vault abstraction. Backends: HashiCorp Vault / AWS Secrets Manager / age."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class SecretsBackend(ABC):
    @abstractmethod
    def resolve(self, ref: str) -> Any:
        """Fetch + decrypt a secret by reference. Caller must not log the value."""

    @abstractmethod
    def audit_access(self, ref: str, *, actor: str, reason: str) -> None:
        """Record who/what/when/why. The secret value itself is never logged."""


class Vault:
    def __init__(self, backend: SecretsBackend) -> None:
        self._backend = backend

    def resolve(self, ref: str, *, actor: str, reason: str) -> Any:
        self._backend.audit_access(ref, actor=actor, reason=reason)
        return self._backend.resolve(ref)
