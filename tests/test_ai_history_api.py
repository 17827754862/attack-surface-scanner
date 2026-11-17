from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api import ai, auth, history
from app.db import AssetSnapshot, Base, User, get_db
from app.security import hash_password


def _client() -> TestClient:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        db.add(User(username="admin", password_hash=hash_password("changeme")))
        db.add(
            AssetSnapshot(
                asset_key="asset-1",
                target="http://dvwa",
                task_id="task-1",
                status="completed",
                finding_count=5,
                risk_group_count=2,
                severity_counts={"medium": 5},
                risk_types=["missing_security_headers"],
            )
        )
        db.commit()

    def override_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI()
    app.include_router(auth.router)
    app.include_router(ai.router)
    app.include_router(history.router)
    app.dependency_overrides[get_db] = override_db
    return TestClient(app)


def _headers(client: TestClient) -> dict[str, str]:
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "changeme"},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_ai_config_masks_api_key() -> None:
    client = _client()
    response = client.put(
        "/api/ai/config",
        headers=_headers(client),
        json={
            "enabled": True,
            "base_url": "https://api.deepseek.com/v1",
            "model": "deepseek-chat",
            "api_key": "super-secret",
        },
    )
    assert response.status_code == 200
    assert response.json()["api_key_configured"] is True
    assert "super-secret" not in response.text
    config = client.get("/api/ai/config", headers=_headers(client))
    assert config.json()["enabled"] is True
    assert "super-secret" not in config.text


def test_history_assets_are_available() -> None:
    client = _client()
    response = client.get("/api/history/assets", headers=_headers(client))
    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["items"][0]["target"] == "http://dvwa"
    detail = client.get("/api/history/assets/asset-1", headers=_headers(client))
    assert detail.status_code == 200
    assert detail.json()["items"][0]["task_id"] == "task-1"
