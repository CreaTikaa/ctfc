"""Background jobs: long searches run in a thread so the browser can poll the progress
and press "Cancel".

Flow:
    POST /api/jobs/<kind>        -> {"job": "<id>"}      (the search starts)
    GET  /api/jobs/<id>          -> {"state", "progress", "result" or "error"}
    POST /api/jobs/<id>/cancel   -> asks the search to stop (Budget.cancel)

Jobs live in memory only; the oldest ones are forgotten after `max_jobs`.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from ctfc.core.budget import Budget


@dataclass
class Job:
    id: str
    kind: str
    budget: Budget
    state: str = "running"  # running | done | error | cancelled
    progress: float = 0.0  # 0..1, from the budget's attempt counter
    result: dict | None = None
    error: str = ""
    created: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "state": self.state,
            "progress": round(self.progress, 3),
            "attempts": self.budget.attempts,
            "result": self.result if self.state in ("done", "cancelled") else None,
            "error": self.error,
        }


class JobManager:
    """Starts jobs in threads and keeps the most recent ones."""

    def __init__(self, max_jobs: int = 20) -> None:
        self.max_jobs = max_jobs
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def start(self, kind: str, work: Callable[[Budget], dict], budget: Budget) -> Job:
        """Run `work(budget)` in a thread. `work` returns the JSON-ready result."""
        job = Job(id=uuid.uuid4().hex[:12], kind=kind, budget=budget)

        def report(done: int, total: int) -> None:
            job.progress = min(0.99, done / max(total, 1))

        budget.on_progress = report
        budget.progress_every = 10

        def run() -> None:
            try:
                job.result = work(budget)
                job.state = "cancelled" if budget.stopped_reason == "cancelled" else "done"
                job.progress = 1.0
            except Exception as exc:  # shown to the user instead of a silent dead thread
                job.state = "error"
                job.error = f"{type(exc).__name__}: {exc}"

        with self._lock:
            self._jobs[job.id] = job
            while len(self._jobs) > self.max_jobs:
                oldest = min(self._jobs.values(), key=lambda item: item.created)
                del self._jobs[oldest.id]
        threading.Thread(target=run, daemon=True).start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None:
            return False
        job.budget.cancel()
        return True
