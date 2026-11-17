from __future__ import annotations

import logging
import urllib.parse
import uuid

import redis
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..celery_app import celery_app
from ..config import settings
from ..db import AuditLog, Task, User, get_db
from ..ephemeral_auth import seal_auth_payload
from ..graph.nodes import initial_node_status
from ..guard import GuardError, normalize_target, validate_task
from ..schemas.task import CustomAuthCreate, TaskCreate, TaskResponse
from ..security import get_current_user


router = APIRouter(prefix="/api/tasks", tags=["tasks"])
redis_client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
logger = logging.getLogger(__name__)


def _ephemeral_auth_key(task_id: str) -> str:
    return f"ephemeral-auth:{task_id}"


def _http_url(value: str, default_scheme: str = "https") -> str:
    raw = value.strip()
    return raw if "://" in raw else f"{default_scheme}://{raw}"


def _validate_custom_auth_origin(
    auth: CustomAuthCreate,
    target: str,
) -> None:
    login = urllib.parse.urlparse(_http_url(auth.login_url))
    if login.scheme not in {"http", "https"} or not login.hostname:
        raise HTTPException(status_code=403, detail="invalid custom login URL")
    target_host = normalize_target(target)
    if login.hostname.lower() != target_host:
        raise HTTPException(
            status_code=403,
            detail="custom login URL must use the same host as the scan target",
        )
    if auth.verification_url:
        verification = urllib.parse.urlparse(_http_url(auth.verification_url))
        if (
            verification.scheme not in {"http", "https"}
            or (verification.hostname or "").lower() != target_host
        ):
            raise HTTPException(
                status_code=403,
                detail="verification URL must use the same host as the scan target",
            )


def _custom_auth_payload(
    auth: CustomAuthCreate,
    target: str,
) -> dict:
    target_url = _http_url(target)
    target_host = normalize_target(target)
    username_field = auth.username_field or (
        "email" if auth.type == "json" else "username"
    )
    password_field = auth.password_field or "password"
    profile = {
        "type": auth.type,
        "label": "Frontend custom login",
        "target_hint": target_url,
        "target_hosts": [target_host],
        "login_url": _http_url(auth.login_url),
        "verification_url": _http_url(auth.verification_url or target_url),
        "method": "POST",
        "username_field": username_field,
        "password_field": password_field,
        "submit_field": auth.submit_field,
        "submit_value": auth.submit_value,
        "token_json_path": auth.token_json_path,
        "token_header": auth.token_header,
        "token_prefix": auth.token_prefix,
        "token_cookie_name": auth.token_cookie_name,
        "logged_in_indicator": auth.logged_in_indicator,
        "logged_out_indicator": auth.logged_out_indicator,
        "success_url_contains": auth.success_url_contains,
    }
    return {
        "profile": profile,
        "username": auth.username,
        "password": auth.password,
    }


def _dispatch_task(
    db: Session,
    task: Task,
    task_name: str,
    username: str,
    *,
    ephemeral_auth: dict | None = None,
) -> None:
    try:
        if ephemeral_auth:
            redis_client.set(
                _ephemeral_auth_key(task.id),
                seal_auth_payload(ephemeral_auth),
                ex=settings.ephemeral_auth_ttl_seconds,
            )
        queued = celery_app.send_task(task_name, args=[task.id])
    except Exception as exc:
        logger.exception("failed to dispatch %s for task %s", task_name, task.id)
        if ephemeral_auth:
            try:
                redis_client.delete(_ephemeral_auth_key(task.id))
            except Exception:
                logger.warning(
                    "failed to clear temporary authentication for task %s",
                    task.id,
                )
        task.status = "failed"
        task.errors = [
            *(task.errors or []),
            f"task dispatch failed: {type(exc).__name__}",
        ]
        db.add(
            AuditLog(
                username=username,
                action="task.dispatch_failed",
                target=task.target,
                task_id=task.id,
                detail={
                    "task_name": task_name,
                    "error_type": type(exc).__name__,
                },
            )
        )
        db.commit()
        raise HTTPException(
            status_code=503,
            detail="task queue unavailable; task was not started",
        ) from exc
    task.celery_task_id = queued.id


def _response(task: Task) -> TaskResponse:
    state = task.resume_state or {}
    report = task.report_json or {}
    return TaskResponse(
        id=task.id,
        target=task.target,
        auth_ref=task.auth_ref or "none",
        status=task.status,
        mode=task.mode,
        tool_profile=task.tool_profile,
        node_status=task.node_status or {},
        errors=task.errors or [],
        blocked_targets=task.blocked_targets or [],
        auth_metrics=state.get("auth_metrics", {}),
        validation_level=task.validation_level or "safe",
        oast_enabled=bool(task.oast_enabled),
        llm_summary=task.llm_summary,
        risk_groups=task.risk_groups or [],
        memory_context=task.memory_context or {},
        findings_count=len(task.findings or []),
        routing_mode=str(state.get("routing_mode") or report.get("routing_mode") or "auto"),
        routing_reason=str(state.get("routing_reason") or report.get("routing_reason") or ""),
        routing_confidence=int(
            state.get("routing_confidence")
            or report.get("routing_confidence")
            or 0
        ),
        next_scan_node=str(state.get("next_scan_node") or ""),
        completed_scan_nodes=list(state.get("completed_scan_nodes") or []),
        scan_decisions=list(state.get("scan_decisions") or report.get("scan_decisions") or []),
    )


@router.post("", response_model=TaskResponse, status_code=202)
def create_task(
    payload: TaskCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TaskResponse:
    ephemeral_auth = None
    if payload.custom_auth:
        payload.auth_ref = "custom"
        _validate_custom_auth_origin(payload.custom_auth, payload.target)
        ephemeral_auth = _custom_auth_payload(payload.custom_auth, payload.target)
    try:
        decision = validate_task(payload)
    except GuardError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    task = Task(
        id=str(uuid.uuid4()),
        target=payload.target,
        auth_ref=decision.auth_ref,
        max_rps=decision.max_rps,
        mode=decision.mode,
        tool_profile=decision.tool_profile,
        validation_level=decision.validation_level,
        oast_enabled=decision.oast_enabled,
        status="queued",
        node_status=initial_node_status(),
        findings=[],
        errors=[],
    )
    db.add(task)
    db.add(
        AuditLog(
            username=user.username,
            action="task.create",
            target=payload.target,
            task_id=task.id,
            detail={
                "mode": payload.mode,
                "max_rps": decision.max_rps,
                "validation_level": decision.validation_level,
                "authorization_confirmed": True,
                "scope": decision.scope,
            },
        )
    )
    db.commit()
    db.refresh(task)
    _dispatch_task(
        db,
        task,
        "run_task",
        user.username,
        ephemeral_auth=ephemeral_auth,
    )
    db.commit()
    db.refresh(task)
    return _response(task)


@router.get("/{task_id}", response_model=TaskResponse)
def get_task(
    task_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TaskResponse:
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return _response(task)


@router.post("/{task_id}/cancel", response_model=TaskResponse)
def cancel_task(
    task_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TaskResponse:
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    redis_client.set(f"cancel:{task_id}", "1", ex=3600)
    if task.celery_task_id:
        celery_app.control.revoke(
            task.celery_task_id,
            terminate=False,
        )
    if task.status in {"queued", "running", "resuming"}:
        task.status = "cancelled"
        db.add(
            AuditLog(
                username=user.username,
                action="task.cancel",
                target=task.target,
                task_id=task.id,
            )
        )
        db.commit()
        db.refresh(task)
    return _response(task)


@router.post("/{task_id}/resume", response_model=TaskResponse)
def resume_task(
    task_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> TaskResponse:
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    if task.status not in {"failed", "cancelled"}:
        raise HTTPException(
            status_code=409,
            detail="only failed or cancelled tasks can be resumed",
        )
    if task.auth_ref == "custom":
        raise HTTPException(
            status_code=409,
            detail="tasks using frontend credentials must be created again",
        )
    task.status = "resuming"
    db.add(
        AuditLog(
            username=user.username,
            action="task.resume",
            target=task.target,
            task_id=task.id,
        )
    )
    db.commit()
    db.refresh(task)
    _dispatch_task(db, task, "resume_task", user.username)
    db.commit()
    db.refresh(task)
    return _response(task)
