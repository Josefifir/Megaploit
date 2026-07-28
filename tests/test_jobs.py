"""
Unit tests for megaploit.core.jobs — JobManager.
"""
from __future__ import annotations

import time
import threading

import pytest

from megaploit.core.jobs import Job, JobManager, JobStatus


class TestJobManager:

    def test_submit_runs_function(self):
        jm = JobManager()
        result_box = []
        jid = jm.submit("test_job", lambda: result_box.append(42))
        jm.wait(jid, timeout=2.0)
        assert 42 in result_box

    def test_submit_returns_id(self):
        jm = JobManager()
        jid = jm.submit("noop", lambda: None)
        assert isinstance(jid, str)
        assert len(jid) == 8

    def test_status_transitions(self):
        jm = JobManager()
        done = threading.Event()
        def slow():
            done.wait(timeout=3)

        jid = jm.submit("slow_job", slow)
        time.sleep(0.05)
        job = jm.get(jid)
        assert job is not None
        assert job.status == JobStatus.RUNNING
        done.set()
        jm.wait(jid, timeout=2.0)
        assert job.status == JobStatus.COMPLETED

    def test_failed_job_status(self):
        jm = JobManager()
        def raises():
            raise RuntimeError("Intentional error")

        jid = jm.submit("bad_job", raises)
        jm.wait(jid, timeout=2.0)
        job = jm.get(jid)
        assert job.status == JobStatus.FAILED
        assert "Intentional error" in job.error

    def test_result_captured(self):
        jm = JobManager()
        jid = jm.submit("returns_42", lambda: 42)
        jm.wait(jid, timeout=2.0)
        assert jm.result(jid) == 42

    def test_kill_sets_stop_event(self):
        jm = JobManager()
        stop_seen = []

        def cooperative(stop_event: threading.Event):
            while not stop_event.is_set():
                time.sleep(0.01)
            stop_seen.append(True)

        jid = jm.submit("coop", cooperative)
        time.sleep(0.05)
        jm.kill(jid)
        jm.wait(jid, timeout=2.0)
        assert stop_seen, "Cooperative function should have seen stop signal"

    def test_kill_nonexistent_returns_false(self):
        jm = JobManager()
        assert jm.kill("nonexistent_id") is False

    def test_list_jobs_returns_dicts(self):
        jm = JobManager()
        jid = jm.submit("list_test", lambda: None)
        jm.wait(jid, timeout=2.0)
        jobs = jm.list_jobs()
        assert isinstance(jobs, list)
        assert len(jobs) >= 1
        job_dict = next(j for j in jobs if j["id"] == jid)
        assert "name" in job_dict
        assert "status" in job_dict
        assert "started" in job_dict

    def test_prune_removes_finished_jobs(self):
        jm = JobManager()
        jid = jm.submit("prune_me", lambda: None)
        jm.wait(jid, timeout=2.0)
        removed = jm.prune()
        assert removed == 1
        assert jm.get(jid) is None

    def test_multiple_concurrent_jobs(self):
        jm = JobManager()
        results = []
        lock = threading.Lock()

        def append_n(n: int):
            time.sleep(0.01)
            with lock:
                results.append(n)

        ids = [jm.submit(f"job_{i}", append_n, i) for i in range(10)]
        for jid in ids:
            jm.wait(jid, timeout=3.0)

        assert sorted(results) == list(range(10))

    def test_get_nonexistent_returns_none(self):
        jm = JobManager()
        assert jm.get("doesnotexist") is None

    def test_started_timestamp_set(self):
        jm = JobManager()
        jid = jm.submit("ts_test", lambda: None)
        jm.wait(jid, timeout=2.0)
        job = jm.get(jid)
        assert job.started.endswith("Z")

    def test_finished_timestamp_set(self):
        jm = JobManager()
        jid = jm.submit("ts_test2", lambda: None)
        jm.wait(jid, timeout=2.0)
        job = jm.get(jid)
        assert job.finished.endswith("Z")

    def test_kill_all(self):
        jm = JobManager()
        stop_events = []

        def wait_for_stop(stop_event: threading.Event):
            stop_events.append(stop_event)
            stop_event.wait(timeout=5)

        ids = [jm.submit(f"killall_{i}", wait_for_stop) for i in range(3)]
        time.sleep(0.05)
        jm.kill_all()
        for jid in ids:
            jm.wait(jid, timeout=2.0)
        for ev in stop_events:
            assert ev.is_set()

    def test_repr(self):
        jm = JobManager()
        assert "JobManager" in repr(jm)


class TestJob:
    def test_to_dict(self):
        job = Job(id="abc12345", name="test", status=JobStatus.RUNNING)
        d = job.to_dict()
        assert d["id"] == "abc12345"
        assert d["name"] == "test"
        assert d["status"] == "running"
