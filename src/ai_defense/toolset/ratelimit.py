"""Rate limiting & concurrency caps (CLAUDE.md policy check #6).

Stateful, so it lives outside the pure PolicyEngine. The dispatcher consults it
immediately before executing a *mutating* change:

  * ``per_host_changes_per_hour`` — caps how many changes a single host may
    receive within a rolling window. Guards against hammering one host.
  * ``fleet_concurrency`` — caps how many changes may be in flight across the
    whole fleet at once.

Check-and-reserve is atomic under the backend lock, so two dispatchers racing on
the last slot cannot both win. A reservation holds a concurrency slot until the
dispatcher calls ``end`` (in a finally), and records the change toward the
per-host window at reserve time (an attempt counts, which is the safe choice).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol


class RateLimiterBackend(Protocol):
    lock: threading.RLock

    def recent_change_count(self, host: str, since: datetime) -> int: ...
    def record_change(self, host: str, ts: datetime) -> None: ...
    def current_concurrency(self) -> int: ...
    def acquire_slot(self) -> None: ...
    def release_slot(self) -> None: ...


class InMemoryRateBackend:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._changes: dict[str, list[datetime]] = {}
        self._concurrency = 0

    def recent_change_count(self, host: str, since: datetime) -> int:
        return sum(1 for t in self._changes.get(host, ()) if t >= since)

    def record_change(self, host: str, ts: datetime) -> None:
        self._changes.setdefault(host, []).append(ts)

    def current_concurrency(self) -> int:
        return self._concurrency

    def acquire_slot(self) -> None:
        self._concurrency += 1

    def release_slot(self) -> None:
        self._concurrency = max(0, self._concurrency - 1)


@dataclass(frozen=True)
class Reservation:
    hosts: tuple[str, ...]


class RateLimiter:
    def __init__(
        self,
        backend: RateLimiterBackend | None = None,
        *,
        per_host_changes_per_hour: int | None = None,
        fleet_concurrency: int | None = None,
        window: timedelta = timedelta(hours=1),
    ) -> None:
        self._backend = backend or InMemoryRateBackend()
        self._per_host = per_host_changes_per_hour
        self._fleet = fleet_concurrency
        self._window = window

    @classmethod
    def from_config(cls, config: dict, backend: RateLimiterBackend | None = None) -> RateLimiter:
        rl = (config or {}).get("rate_limits", {})
        return cls(
            backend,
            per_host_changes_per_hour=rl.get("per_host_changes_per_hour"),
            fleet_concurrency=rl.get("fleet_concurrency"),
        )

    def try_begin(self, hosts: list[str], now: datetime) -> tuple[Reservation | None, str | None]:
        """Atomically check both caps and, if clear, reserve a slot + record the
        changes. Returns (reservation, None) on success or (None, reason)."""
        with self._backend.lock:
            if self._fleet is not None and self._backend.current_concurrency() >= self._fleet:
                return None, f"fleet concurrency cap {self._fleet} reached"
            if self._per_host is not None:
                since = now - self._window
                for h in hosts:
                    if self._backend.recent_change_count(h, since) >= self._per_host:
                        return None, (
                            f"host '{h}' exceeded change rate cap "
                            f"{self._per_host}/{self._window}"
                        )
            self._backend.acquire_slot()
            for h in hosts:
                self._backend.record_change(h, now)
            return Reservation(tuple(hosts)), None

    def end(self, reservation: Reservation) -> None:
        with self._backend.lock:
            self._backend.release_slot()
