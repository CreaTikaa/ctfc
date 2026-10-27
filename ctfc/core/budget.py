"""Limit how long a brute force may run, report progress, and allow cancelling.

Every search loop (auto decoding, XOR, key hunting...) receives a `Budget` and calls
`budget.spend()` once per attempt. When `spend()` returns False, the loop stops.

    budget = Budget(max_attempts=1000, max_seconds=5)
    for key in keys:
        if not budget.spend():
            break
        ...
    print(budget.summary())   # "412 attempts in 0.3 s (stopped: none)"
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class Budget:
    """An attempt counter with a time limit and a cancel flag."""

    max_attempts: int = 10_000
    max_seconds: float = 10.0
    # Called every `progress_every` attempts with (attempts_done, max_attempts).
    on_progress: Callable[[int, int], None] | None = None
    progress_every: int = 100
    cancel_event: threading.Event = field(default_factory=threading.Event)
    attempts: int = 0
    stopped_reason: str = ""  # "", "attempts", "time" or "cancelled"
    _start: float = field(default_factory=time.monotonic)

    def spend(self, count: int = 1) -> bool:
        """Count `count` attempts. Return False when the loop must stop."""
        if self.stopped_reason:
            return False
        self.attempts += count
        if self.cancel_event.is_set():
            self.stopped_reason = "cancelled"
        elif self.attempts > self.max_attempts:
            self.stopped_reason = "attempts"
        elif time.monotonic() - self._start > self.max_seconds:
            self.stopped_reason = "time"
        if self.on_progress and self.attempts % self.progress_every == 0:
            self.on_progress(self.attempts, self.max_attempts)
        return not self.stopped_reason

    def cancel(self) -> None:
        """Ask the loop using this budget to stop (safe to call from another thread)."""
        self.cancel_event.set()

    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def summary(self) -> str:
        """One line for the user: how much was tried and why it stopped."""
        why = {
            "": "search finished",
            "attempts": "attempt budget reached",
            "time": "time budget reached",
            "cancelled": "cancelled",
        }[self.stopped_reason]
        return f"{self.attempts} attempts in {self.elapsed():.2f} s ({why})"
