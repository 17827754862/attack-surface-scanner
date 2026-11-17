from __future__ import annotations

from types import SimpleNamespace

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import auth
from app.api.events import format_sse
from app.api import tasks as tasks_api
from app.db import AuditLog, Base, Task, User, get_db
from app.ephemeral_auth import open_auth_payload
from app.guard import GuardDecision
from app.security import get_current_user, hash_password


def _client_bundle() -> tuple[TestClient, sessionmaker]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        db.add(User(username="admin", password_hash=hash_password("changeme")))
        db.commit()

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI()
    app.include_router(auth.router)
    app.include_router(tasks_api.router)

    @app.get("/protected")
    def protected(_user=Depends(get_current_user)):
        return {"ok": True}

    app.dependency_overrides[get_db] = override_db
    return TestClient(app), factory


def _client() -> TestClient:
    return _client_bundle()[0]


def test_jwt_login_and_protected_endpoint() -> None:
    client = _client()
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    assert client.get("/protected").status_code == 401
    assert client.get(
        "/protected",
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 200


def test_sse_message_format() -> None:
    assert format_sse('{"node":"web_scan"}') == 'data: {"node":"web_scan"}\n\n'


def test_create_task_requires_authorization_confirmation() -> None:
    client, factory = _client_bundle()
    token = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    ).json()["access_token"]

    response = client.post(
        "/api/tasks",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target": "https://www.school.edu.cn/",
            "auth_ref": "none",
            "max_rps": 1,
            "mode": "passive",
        },
    )

    assert response.status_code == 403
    assert "authorization confirmation" in response.json()["detail"]
    with factory() as db:
        assert db.query(Task).count() == 0


def test_cancel_task_uses_authenticated_user(monkeypatch) -> None:
    client, factory = _client_bundle()
    task_id = "00000000-0000-0000-0000-000000000001"
    with factory() as db:
        db.add(
            Task(
                id=task_id,
                target="http://dvwa",
                auth_ref="local-dvwa",
                status="running",
                celery_task_id="celery-1",
                node_status={},
                findings=[],
                errors=[],
                blocked_targets=[],
            )
        )
        db.commit()

    monkeypatch.setattr(tasks_api.redis_client, "set", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        tasks_api.celery_app.control,
        "revoke",
        lambda *_args, **_kwargs: None,
    )
    token = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    ).json()["access_token"]
    response = client.post(
        f"/api/tasks/{task_id}/cancel",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    with factory() as db:
        audit = db.query(AuditLog).filter_by(task_id=task_id, action="task.cancel").one()
        assert audit.username == "admin"


def test_create_task_marks_failed_when_queue_is_unavailable(monkeypatch) -> None:
    client, factory = _client_bundle()
    monkeypatch.setattr(
        tasks_api,
        "validate_task",
        lambda payload: GuardDecision(
            target=payload.target,
            host="juice-shop",
            scope=["juice-shop"],
            auth_ref=payload.auth_ref,
            max_rps=payload.max_rps,
            mode=payload.mode,
            tool_profile=payload.tool_profile,
            validation_level=payload.validation_level,
            oast_enabled=False,
            allowed_cidrs=["172.16.0.0/12"],
            resolved_ips=["172.19.0.12"],
        ),
    )

    def fail_dispatch(*_args, **_kwargs):
        raise RuntimeError("redis unavailable")

    monkeypatch.setattr(tasks_api.celery_app, "send_task", fail_dispatch)
    token = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    ).json()["access_token"]
    response = client.post(
        "/api/tasks",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target": "http://juice-shop:3000",
            "auth_ref": "local-juice-auth",
            "authorization_confirmed": True,
            "mode": "active",
        },
    )

    assert response.status_code == 503
    assert "task queue unavailable" in response.json()["detail"]
    with factory() as db:
        task = db.query(Task).one()
        assert task.status == "failed"
        assert task.errors == ["task dispatch failed: RuntimeError"]
        audit = db.query(AuditLog).filter_by(action="task.dispatch_failed").one()
        assert audit.task_id == task.id


def test_custom_frontend_credentials_are_encrypted_and_not_persisted(
    monkeypatch,
) -> None:
    client, factory = _client_bundle()
    monkeypatch.setattr(
        tasks_api,
        "validate_task",
        lambda payload: GuardDecision(
            target=payload.target,
            host="portal.test",
            scope=["portal.test"],
            auth_ref=payload.auth_ref,
            max_rps=payload.max_rps,
            mode=payload.mode,
            tool_profile=payload.tool_profile,
            validation_level=payload.validation_level,
            oast_enabled=False,
            allowed_cidrs=[],
            resolved_ips=["192.0.2.10"],
        ),
    )
    stored: dict[str, str] = {}
    monkeypatch.setattr(
        tasks_api.redis_client,
        "set",
        lambda key, value, ex: stored.update({"key": key, "value": value, "ttl": ex}),
    )
    monkeypatch.setattr(tasks_api.redis_client, "delete", lambda _key: True)
    monkeypatch.setattr(
        tasks_api.celery_app,
        "send_task",
        lambda *_args, **_kwargs: SimpleNamespace(id="celery-custom"),
    )

    token = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    ).json()["access_token"]
    response = client.post(
        "/api/tasks",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "target": "http://portal.test",
            "authorization_confirmed": True,
            "mode": "active",
            "custom_auth": {
                "type": "auto",
                "login_url": "http://portal.test/login",
                "username": "scanner@example.test",
                "password": "never-store-this",
                "logged_in_indicator": "scanner@example.test",
            },
        },
    )

    assert response.status_code == 202
    assert stored["key"].startswith("ephemeral-auth:")
    assert stored["ttl"] == 1800
    assert "never-store-this" not in stored["value"]
    payload = open_auth_payload(stored["value"])
    assert payload["password"] == "never-store-this"
    with factory() as db:
        task = db.query(Task).one()
        assert task.auth_ref == "custom"
        assert task.celery_task_id == "celery-custom"
        audit = db.query(AuditLog).filter_by(action="task.create").one()
        assert "never-store-this" not in str(audit.detail)
