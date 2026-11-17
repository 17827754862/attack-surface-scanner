from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.ai_config import decrypt_api_key, encrypt_api_key
from app.db import AssetSnapshot, Base, Task
from app.memory import list_assets, load_memory_context, save_snapshot
from app.risk_groups import build_risk_groups


def test_risk_groups_collapse_url_instances() -> None:
    findings = [
        {
            "source": "zap",
            "host": "dvwa",
            "port": 80,
            "url": "http://dvwa/a",
            "vuln_type": "missing_security_headers",
            "severity": "medium",
            "confidence": 60,
            "fingerprint": "a",
            "evidence": {"header": "csp"},
            "raw": {"pluginId": "10038"},
            "also_reported_by": [],
        },
        {
            "source": "wapiti",
            "host": "dvwa",
            "port": 80,
            "url": "http://dvwa/b",
            "vuln_type": "missing_security_headers",
            "severity": "low",
            "confidence": 55,
            "fingerprint": "b",
            "evidence": {"header": "csp"},
            "raw": {"pluginId": "10038"},
            "also_reported_by": [],
        },
    ]
    groups = build_risk_groups(findings)
    assert len(groups) == 1
    assert groups[0]["instance_count"] == 2
    assert groups[0]["affected_url_count"] == 2
    assert groups[0]["sources"] == ["wapiti", "zap"]


def test_ai_key_round_trip() -> None:
    encrypted = encrypt_api_key("secret-key")
    assert encrypted != "secret-key"
    assert decrypt_api_key(encrypted) == "secret-key"


def test_asset_memory_delta() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        db.add(
            Task(
                id="t1",
                target="http://dvwa",
                auth_ref="local-dvwa",
                status="completed",
                node_status={},
                findings=[],
                errors=[],
                risk_groups=[],
            )
        )
        db.commit()
        save_snapshot(
            db,
            target="http://dvwa",
            task_id="t1",
            status="completed",
            findings=[{"severity": "medium"}],
            groups=[{"vuln_type": "sql_injection"}],
        )
        memory = load_memory_context(db, "http://dvwa")
        assert memory["scan_count"] == 1
        assert memory["previous"]["task_id"] == "t1"
        assets = list_assets(db)
        assert assets[0]["risk_group_count"] == 1
        assert db.query(AssetSnapshot).count() == 1
