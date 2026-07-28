"""
megaploit.core.jobs
~~~~~~~~~~~~~~~~~~~~
Background jobs engine for Megaploit.

Allows long-running module executions, session commands, and arbitrary
callables to run as named background jobs that can be listed and killed
from the CLI.

Usage::

    from megaploit.core.jobs import job_manager

    # Submit a callable
    jid = job_manager.submit("tcp_scan_10.0.0.0/24", my_callable, *args, **kwargs)

    # List running jobs
    for j in job_manager.list_jobs():
        print(j["id"], j["name"], j["status"])

    # Kill a job
    job_manager.kill(jid)
"""

from __future__ import annotations

import datetime
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

__all__ = ["JobStatus", "Job", "JobManager", "job_manager"]


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

class JobStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    KILLED    = "killed"


# ---------------------------------------------------------------------------
# Job descriptor
# ---------------------------------------------------------------------------

@dataclass
class Job:
    """Represents a single background job."""
    id:       str
    name:     str
    status:   JobStatus
    started:  str           = ""
    finished: str           = ""
    error:    str           = ""
    result:   Any           = None
    _thread:  Optional[threading.Thread] = field(default=None, repr=False, compare=False)
    _stop:    threading.Event             = field(default_factory=threading.Event, repr=False, compare=False)

    def stop_flag(self) -> threading.Event:
        return self._stop

    def to_dict(self) -> dict:
        return {
            "id":       self.id,
            "name":     self.name,
            "status":   self.status.value,
            "started":  self.started,
            "finished": self.finished,
            "error":    self.error,
        }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class JobManager:
    """
    Thread-based job manager.

    Jobs are Python callables executed in daemon threads.
    A stop ``threading.Event`` is passed as the first argument to the callable
    if its signature includes ``stop_event`` (checked by name), allowing
    cooperative cancellation.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Submit
    # ------------------------------------------------------------------

    def submit(
        self,
        name: str,
        fn: Callable,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        """
        Run *fn* in a background daemon thread.

        Returns the job ID string.
        """
        jid  = str(uuid.uuid4())[:8]
        stop = threading.Event()
        job  = Job(
            id=jid,
            name=name[:64],
            status=JobStatus.PENDING,
        )

        def _runner() -> None:
            job.status  = JobStatus.RUNNING
            job.started = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
            try:
                # Inject stop_event if the callable accepts it
                import inspect
                sig = inspect.signature(fn)
                if "stop_event" in sig.parameters:
                    kwargs["stop_event"] = stop
                job.result = fn(*args, **kwargs)
                job.status = JobStatus.COMPLETED
            except Exception as exc:
                job.status = JobStatus.FAILED
                job.error  = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            finally:
                job.finished = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

        t = threading.Thread(target=_runner, name=f"job-{jid}", daemon=True)
        job._thread = t
        job._stop   = stop

        with self._lock:
            self._jobs[jid] = job

        job.status = JobStatus.PENDING
        t.start()
        return jid

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def list_jobs(self) -> list[dict]:
        with self._lock:
            return [j.to_dict() for j in self._jobs.values()]

    def get(self, jid: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(jid)

    def result(self, jid: str) -> Any:
        job = self.get(jid)
        return job.result if job else None

    # ------------------------------------------------------------------
    # Kill
    # ------------------------------------------------------------------

    def kill(self, jid: str) -> bool:
        """
        Signal a job to stop.

        The callable must honour ``stop_event.is_set()`` for cooperative
        cancellation.  Returns True if the job was found.
        """
        job = self.get(jid)
        if job is None:
            return False
        job._stop.set()
        if job.status == JobStatus.RUNNING:
            job.status = JobStatus.KILLED
        return True

    def kill_all(self) -> None:
        with self._lock:
            jids = list(self._jobs.keys())
        for jid in jids:
            self.kill(jid)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def prune(self) -> int:
        """Remove completed/failed/killed jobs.  Returns count removed."""
        with self._lock:
            dead = [
                jid for jid, j in self._jobs.items()
                if j.status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.KILLED)
            ]
            for jid in dead:
                del self._jobs[jid]
        return len(dead)

    def wait(self, jid: str, timeout: float = 30.0) -> bool:
        """Wait for a job to finish.  Returns True if it finished in time."""
        job = self.get(jid)
        if job is None:
            return False
        if job._thread:
            job._thread.join(timeout=timeout)
        return job.status not in (JobStatus.PENDING, JobStatus.RUNNING)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        running = sum(1 for j in self._jobs.values() if j.status == JobStatus.RUNNING)
        return f"<JobManager  {len(self._jobs)} total  {running} running>"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

job_manager = JobManager()
