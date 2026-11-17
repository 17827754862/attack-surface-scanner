from __future__ import annotations

import time

import pytest

from app.adapters.base import AdapterCancelled, BaseAdapter
from worker import tasks as worker_tasks
from worker.tasks import _required_capabilities_ready, _resume_node


def test_resume_prefers_failed_node() -> None:
    state = {
        "resume_from": "nuclei_scan",
        "node_status": {
            "recon": "done",
            "nuclei_scan": "failed",
            "merge_and_score": "pending",
        },
    }
    assert _resume_node(state) == "nuclei_scan"


def test_resume_falls_back_to_pending() -> None:
    assert _resume_node(
        {"node_status": {"recon": "done", "dns_resolve": "pending"}}
    ) == "dns_resolve"


def test_cancelled_workflow_resumes_from_earliest_failed_node() -> None:
    assert _resume_node(
        {
            "cancelled": True,
            "node_status": {
                "recon": "done",
                "dns_resolve": "done",
                "http_probe": "failed",
                "port_scan": "failed",
                "router": "done",
                "merge_and_score": "pending",
            },
        }
    ) == "http_probe"


def test_capability_readiness_requires_zap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENVAS_ENABLED", "true")
    capabilities = {
        "zap": {"available": False},
        "oast": {"available": True},
        "openvas": {"available": True},
    }
    assert not _required_capabilities_ready(capabilities)
    capabilities["zap"]["available"] = True
    assert _required_capabilities_ready(capabilities)


def test_subprocess_process_group_is_cancelled() -> None:
    class Adapter(BaseAdapter):
        name = "test"
        def run(self, target_or_input, options):
            return []

    adapter = Adapter(cancel_check=lambda: True)
    started = time.monotonic()
    with pytest.raises(AdapterCancelled):
        adapter._run(["sh", "-c", "sleep 10"])
    assert time.monotonic() - started < 3


def test_mark_failed_writes_status(monkeypatch: pytest.MonkeyPatch) -> None:
    class DummyTask:
        status = "running"
        errors = []

    class DummyDB:
        def __init__(self): self.task = DummyTask(); self.committed = False
        def get(self, _model, _id): return self.task
        def commit(self): self.committed = True
        def close(self): pass

    db = DummyDB()
    monkeypatch.setattr(worker_tasks, "SessionLocal", lambda: db)
    worker_tasks._mark_failed("id", ValueError("password=secret"))
    assert db.task.status == "failed"
    assert db.task.errors == ["password=***"]
    assert db.committed
