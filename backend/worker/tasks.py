from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

import redis
from celery.signals import worker_ready
from celery.utils.log import get_task_logger

from app.capabilities import write_capabilities
from app.auth_session import (
    AuthCredentialOverride,
    AuthProfile,
    use_auth_credentials,
)
from app.celery_app import celery_app
from app.config import settings
from app.db import SessionLocal, Task
from app.ephemeral_auth import open_auth_payload
from app.graph.build import build_graph
from app.graph.nodes import (
    NODE_NAMES,
    initial_node_status,
    set_cancel_checker,
)
from app.memory import load_memory_context, save_snapshot
from app.redaction import redact, redact_text


logger = get_task_logger(__name__)
redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
NODE_ORDER = list(NODE_NAMES)

SCAN_START_NODES = {
    "web_scan",
    "nuclei_scan",
    "js_secret_scan",
    "api_fuzz",
    "k8s_audit",
    "server_baseline",
    "host_vuln_scan",
}


def _ephemeral_auth_key(task_id: str) -> str:
    return f"ephemeral-auth:{task_id}"


def _load_ephemeral_auth(task_id: str) -> AuthCredentialOverride | None:
    sealed = redis_client.get(_ephemeral_auth_key(task_id))
    if not sealed:
        return None
    payload = open_auth_payload(str(sealed))
    profile = AuthProfile.model_validate(payload.get("profile") or {})
    username = str(payload.get("username") or "")
    password = str(payload.get("password") or "")
    if not username or not password:
        raise ValueError("temporary authentication credentials are incomplete")
    return AuthCredentialOverride(
        auth_ref="custom",
        profile=profile,
        username=username,
        password=password,
    )


def _clear_ephemeral_auth(task_id: str) -> None:
    redis_client.delete(_ephemeral_auth_key(task_id))


def _initial_state(
    task: Task,
    capabilities: dict[str, Any],
    memory_context: dict[str, Any],
) -> dict[str, Any]:
    return {
        "task_id": task.id,
        "target": task.target,
        "auth_ref": task.auth_ref,
        "max_rps": task.max_rps,
        "mode": task.mode,
        "tool_profile": task.tool_profile,
        "validation_level": task.validation_level,
        "oast_enabled": bool(task.oast_enabled),
        "status": "running",
        "subdomains": [],
        "resolved_hosts": [],
        "live_endpoints": [],
        "port_findings": [],
        "vuln_findings": [],
        "api_findings": [],
        "k8s_findings": [],
        "secret_findings": [],
        "takeover_findings": [],
        "findings": [],
        "execution_trace": [],
        "node_status": initial_node_status(),
        "errors": [],
        "blocked_targets": [],
        "cancelled": False,
        "capabilities": capabilities,
        "next_scan_node": "",
        "completed_scan_nodes": [],
        "scan_decisions": [],
        "routing_mode": "auto",
        "routing_reason": "",
        "routing_confidence": 0,
        "routing_error": "",
        "llm_summary": {},
        "risk_groups": [],
        "memory_context": memory_context,
        "auth_metrics": {},
    }


def _required_capabilities_ready(capabilities: dict[str, Any]) -> bool:
    required = {"zap", "oast"}
    if os.getenv("OPENVAS_ENABLED", "").strip().lower() == "true":
        required.add("openvas")
    return all(
        bool((capabilities.get(name) or {}).get("available"))
        for name in required
    )


def _refresh_capabilities() -> None:
    delays = iter((0, 2, 5, 10, 20, 30, 30, 30, 30))
    while True:
        delay = next(delays, 60)
        if delay:
            time.sleep(delay)
        try:
            capabilities = write_capabilities()
            if _required_capabilities_ready(capabilities):
                break
        except Exception as exc:
            logger.warning("capability probe failed: %s", redact_text(str(exc)))

    while True:
        time.sleep(60)
        try:
            write_capabilities()
        except Exception as exc:
            logger.warning("capability refresh failed: %s", redact_text(str(exc)))


@worker_ready.connect
def _write_startup_capabilities(**_kwargs) -> None:
    threading.Thread(
        target=_refresh_capabilities,
        name="capability-refresh",
        daemon=True,
    ).start()


def _event_sink(task_id: str):
    def sink(event: dict[str, Any]) -> None:
        event = redact(event)
        channel = f"task:{task_id}:events"
        redis_client.publish(channel, json.dumps(event, ensure_ascii=False))
        if event.get("event") not in {
            "on_chain_start",
            "on_chain_end",
            "on_chain_error",
        }:
            return
        local_db = SessionLocal()
        try:
            local_task = local_db.get(Task, task_id)
            if local_task is None:
                return
            node = str(event.get("node") or "")
            node_status = dict(local_task.node_status or {})
            node_status[node] = str(
                event.get("status")
                or ("running" if event.get("event") == "on_chain_start" else "done")
            )
            local_task.node_status = node_status
            if event.get("event") == "on_chain_error" and event.get("error"):
                errors = list(local_task.errors or [])
                errors.append(redact_text(str(event["error"])))
                local_task.errors = errors
            local_db.commit()
        finally:
            local_db.close()

    return sink


def _read_checkpoint_state(graph: Any, task_id: str) -> dict[str, Any] | None:
    try:
        snapshot = graph.get_state(
            config={"configurable": {"thread_id": task_id}}
        )
        if snapshot and snapshot.values:
            return dict(snapshot.values)
    except Exception as exc:
        logger.warning("checkpoint read failed: %s", redact_text(str(exc)))
    return None


def _resume_node(state: dict[str, Any]) -> str:
    status = state.get("node_status") or {}
    for name in NODE_ORDER:
        if status.get(name) == "failed":
            return name
    if state.get("resume_from"):
        return str(state["resume_from"])
    for name in NODE_ORDER:
        if status.get(name) in {"cancelled", "running"}:
            return name
    for name in NODE_ORDER:
        if status.get(name) == "pending":
            return name
    return "merge_and_score"


def _persist_result(
    task_id: str,
    result: dict[str, Any],
    status: str | None = None,
) -> None:
    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if task is None:
            return
        findings = result.get("findings") or []
        errors = [redact_text(str(item)) for item in result.get("errors") or []]
        report = result.get("report_result") or {}
        task.status = status or str(result.get("status") or "completed")
        task.node_status = result.get("node_status", initial_node_status())
        task.findings = findings
        task.errors = errors
        task.blocked_targets = result.get("blocked_targets") or []
        task.resume_state = result
        task.risk_groups = result.get("risk_groups") or []
        task.memory_context = result.get("memory_context") or {}
        task.report_html = report.get("html")
        task.workflow_png = report.get("png")
        task.workflow_mmd = report.get("mermaid")
        task.llm_summary = (result.get("llm_summary") or {}).get("text")
        report_json_path = report.get("json")
        if report_json_path and Path(report_json_path).exists():
            task.report_json = json.loads(
                Path(report_json_path).read_text(encoding="utf-8")
            )
        db.commit()
        save_snapshot(
            db,
            target=task.target,
            task_id=task.id,
            status=task.status,
            findings=findings,
            groups=task.risk_groups or [],
        )
    finally:
        db.close()


def _mark_failed(task_id: str, exc: Exception) -> None:
    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if task is None:
            return
        task.status = "failed"
        errors = list(task.errors or [])
        errors.append(redact_text(str(exc)))
        task.errors = errors
        db.commit()
    finally:
        db.close()


def _execute(task_id: str, resume: bool = False) -> dict[str, Any]:
    if resume:
        redis_client.delete(f"cancel:{task_id}")
    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if task is None:
            return {"status": "missing", "task_id": task_id}
        task.status = "resuming" if resume else "running"
        db.commit()
        task_snapshot = task
        memory_context = load_memory_context(db, task.target)
        capabilities = write_capabilities()
    finally:
        db.close()

    set_cancel_checker(lambda: bool(redis_client.get(f"cancel:{task_id}")))
    try:
        from langgraph.checkpoint.postgres import PostgresSaver

        dsn = settings.database_url.replace("postgresql+psycopg://", "postgresql://")
        checkpointer_cm = PostgresSaver.from_conn_string(dsn)
        with checkpointer_cm as checkpointer:
            checkpointer.setup()
            graph = build_graph(
                checkpointer=checkpointer,
                event_sink=_event_sink(task_id),
            )
            if resume:
                resumed = (
                    _read_checkpoint_state(graph, task_id)
                    or task_snapshot.resume_state
                )
                if not resumed:
                    resumed = _initial_state(
                        task_snapshot,
                        capabilities,
                        memory_context,
                    )
                    start_at = None
                else:
                    start_at = _resume_node(resumed)
                resumed["status"] = "running"
                resumed["cancelled"] = False
                resumed["resuming"] = True
                resumed.pop("resume_from", None)
                resumed["errors"] = [
                    item
                    for item in resumed.get("errors", [])
                    if "task_cancelled" not in str(item)
                ]
                node_status = dict(resumed.get("node_status") or initial_node_status())
                if start_at:
                    node_status[start_at] = "pending"
                resumed["node_status"] = node_status
                if start_at:
                    graph = build_graph(
                        checkpointer=checkpointer,
                        event_sink=_event_sink(task_id),
                        start_at=start_at,
                    )
                result = graph.invoke(
                    resumed,
                    config={
                        "configurable": {
                            "thread_id": f"{task_id}:resume:{int(time.time())}"
                        },
                        "recursion_limit": 64,
                    },
                )
            else:
                result = graph.invoke(
                    _initial_state(task_snapshot, capabilities, memory_context),
                    config={
                        "configurable": {"thread_id": task_id},
                        "recursion_limit": 64,
                    },
                )
    except Exception as exc:
        logger.exception("checkpoint execution failed: %s", redact_text(str(exc)))
        graph = build_graph(
            checkpointer=None,
            event_sink=_event_sink(task_id),
        )
        fallback = (
            task_snapshot.resume_state
            if resume and task_snapshot.resume_state
            else _initial_state(task_snapshot, capabilities, memory_context)
        )
        result = graph.invoke(fallback, config={"recursion_limit": 64})

    cargo_cancel = redis_client.get(f"cancel:{task_id}")
    status = str(result.get("status") or "completed")
    if cargo_cancel or result.get("cancelled"):
        status = "cancelled"
    _persist_result(task_id, result, status)
    findings = result.get("findings") or []
    return {
        "task_id": task_id,
        "status": status,
        "findings": len(findings),
        "errors": result.get("errors") or [],
    }


@celery_app.task(
    name="run_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    max_retries=2,
)
def run_task(self, task_id: str) -> dict[str, Any]:
    override = _load_ephemeral_auth(task_id)
    completed = False
    try:
        if override:
            with use_auth_credentials(override):
                result = _execute(task_id, resume=False)
        else:
            result = _execute(task_id, resume=False)
        completed = True
        return result
    except Exception as exc:
        _mark_failed(task_id, exc)
        if self.request.retries >= self.max_retries:
            _clear_ephemeral_auth(task_id)
        raise
    finally:
        if completed:
            _clear_ephemeral_auth(task_id)
        set_cancel_checker(lambda: False)


@celery_app.task(
    name="resume_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True,
    max_retries=2,
)
def resume_task(self, task_id: str) -> dict[str, Any]:
    override = _load_ephemeral_auth(task_id)
    completed = False
    try:
        if override:
            with use_auth_credentials(override):
                result = _execute(task_id, resume=True)
        else:
            result = _execute(task_id, resume=True)
        completed = True
        return result
    except Exception as exc:
        _mark_failed(task_id, exc)
        if self.request.retries >= self.max_retries:
            _clear_ephemeral_auth(task_id)
        raise
    finally:
        if completed:
            _clear_ephemeral_auth(task_id)
        set_cancel_checker(lambda: False)
