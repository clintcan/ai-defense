"""aws adapter — wraps only reviewed operations. TODO: implement via official SDK."""

from __future__ import annotations

from .base import CloudAdapter


class AwsAdapter(CloudAdapter):
    provider = "aws"
    # Credentials are resolved by the toolset from the vault at call time,
    # never stored on the adapter instance or passed by the planner.
