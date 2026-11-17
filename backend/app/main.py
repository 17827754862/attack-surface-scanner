from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .api import (
    ai,
    audit,
    auth,
    auth_profiles,
    events,
    findings,
    health,
    history,
    report,
    tasks,
)
from .config import settings
from .db import Base, SessionLocal, User, engine, migrate_schema
from .memory import backfill_snapshots
from .security import hash_password


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    migrate_schema()
    db: Session = SessionLocal()
    try:
        if db.query(User).filter(User.username == settings.admin_username).first() is None:
            db.add(
                User(
                    username=settings.admin_username,
                    password_hash=hash_password(settings.admin_password),
                )
            )
            db.commit()
        backfill_snapshots(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Attack Surface Scanner", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(auth_profiles.router)
app.include_router(health.router)
app.include_router(audit.router)
app.include_router(ai.router)
app.include_router(history.router)
app.include_router(tasks.router)
app.include_router(events.router)
app.include_router(findings.router)
app.include_router(report.router)
