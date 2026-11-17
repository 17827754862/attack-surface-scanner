from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator

from sqlalchemy import JSON, Boolean, DateTime, String, Text, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(500))
    auth_ref: Mapped[str] = mapped_column(String(120))
    max_rps: Mapped[int] = mapped_column(default=5)
    mode: Mapped[str] = mapped_column(String(20), default="active")
    tool_profile: Mapped[str] = mapped_column(
        String(40),
        default="full_agent",
    )
    validation_level: Mapped[str] = mapped_column(String(20), default="safe")
    oast_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    node_status: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    errors: Mapped[list[str]] = mapped_column(JSON, default=list)
    blocked_targets: Mapped[list[str]] = mapped_column(JSON, default=list)
    resume_state: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    llm_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_groups: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    memory_context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    workflow_png: Mapped[str | None] = mapped_column(String(500), nullable=True)
    workflow_mmd: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(80), index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    target: Mapped[str] = mapped_column(String(500), default="")
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AssetSnapshot(Base):
    __tablename__ = "asset_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    asset_key: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(500), index=True)
    task_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(30), default="completed")
    finding_count: Mapped[int] = mapped_column(default=0)
    risk_group_count: Mapped[int] = mapped_column(default=0)
    severity_counts: Mapped[dict[str, int]] = mapped_column(JSON, default=dict)
    risk_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AIConfig(Base):
    __tablename__ = "ai_config"

    id: Mapped[int] = mapped_column(primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    base_url: Mapped[str] = mapped_column(String(500), default="")
    model: Mapped[str] = mapped_column(String(120), default="deepseek-chat")
    api_key_ciphertext: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class AIAnalysisCache(Base):
    __tablename__ = "ai_analysis_cache"

    cache_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    model: Mapped[str] = mapped_column(String(120), default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def migrate_schema() -> None:
    if engine.dialect.name != "postgresql":
        return
    statements = [
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS blocked_targets JSON DEFAULT '[]'::json",
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS resume_state JSON",
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS celery_task_id VARCHAR(80)",
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS llm_summary TEXT",
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS tool_profile VARCHAR(40) DEFAULT 'full_agent'",
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS validation_level VARCHAR(20) DEFAULT 'safe'",
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS oast_enabled BOOLEAN DEFAULT FALSE",
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS risk_groups JSON DEFAULT '[]'::json",
        "ALTER TABLE tasks ADD COLUMN IF NOT EXISTS memory_context JSON DEFAULT '{}'::json",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
