from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field


DATABASE = Path(os.getenv("OAST_DATABASE", "/data/oast.db"))
SECRET = os.getenv("OAST_SECRET", "local-oast-secret")
PUBLIC_BASE_URL = os.getenv(
    "OAST_PUBLIC_BASE_URL",
    "http://oast:8001",
).rstrip("/")

app = FastAPI(title="Attack Surface Scanner OAST")


class TokenRequest(BaseModel):
    label: str = Field(default="", max_length=200)


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS tokens (
              token TEXT PRIMARY KEY,
              label TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS hits (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              token TEXT NOT NULL,
              method TEXT NOT NULL,
              path TEXT NOT NULL,
              query TEXT NOT NULL,
              source TEXT NOT NULL,
              headers TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()
        yield connection
    finally:
        connection.close()


def require_secret(value: str | None) -> None:
    if not value or not secrets.compare_digest(value, SECRET):
        raise HTTPException(status_code=401, detail="invalid callback service secret")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/health")
def health() -> dict[str, bool]:
    with database():
        pass
    return {"ok": True}


@app.post("/api/tokens")
def create_token(
    payload: TokenRequest,
    x_oast_secret: str | None = Header(default=None),
) -> dict[str, str]:
    require_secret(x_oast_secret)
    token = secrets.token_urlsafe(24)
    with database() as connection:
        connection.execute(
            "INSERT INTO tokens(token, label, created_at) VALUES(?, ?, ?)",
            (token, payload.label, now()),
        )
        connection.commit()
    return {
        "token": token,
        "callback_url": f"{PUBLIC_BASE_URL}/cb/{token}",
    }


@app.get("/api/tokens/{token}")
def token_hits(
    token: str,
    x_oast_secret: str | None = Header(default=None),
) -> dict:
    require_secret(x_oast_secret)
    with database() as connection:
        token_row = connection.execute(
            "SELECT token, label, created_at FROM tokens WHERE token = ?",
            (token,),
        ).fetchone()
        if token_row is None:
            raise HTTPException(status_code=404, detail="token not found")
        rows = connection.execute(
            """
            SELECT method, path, query, source, headers, created_at
            FROM hits WHERE token = ? ORDER BY id
            """,
            (token,),
        ).fetchall()
    return {
        **dict(token_row),
        "hits": [
            {
                **dict(row),
                "headers": json.loads(row["headers"]),
            }
            for row in rows
        ],
    }


@app.api_route("/cb/{token}", methods=["GET", "POST", "PUT", "PATCH"])
async def callback(token: str, request: Request) -> Response:
    with database() as connection:
        exists = connection.execute(
            "SELECT 1 FROM tokens WHERE token = ?",
            (token,),
        ).fetchone()
        if exists is None:
            raise HTTPException(status_code=404, detail="token not found")
        safe_headers = {
            key: value[:1000]
            for key, value in request.headers.items()
            if key.lower()
            not in {"authorization", "cookie", "proxy-authorization", "x-api-key"}
        }
        connection.execute(
            """
            INSERT INTO hits(
              token, method, path, query, source, headers, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                token,
                request.method,
                request.url.path,
                request.url.query,
                request.client.host if request.client else "",
                json.dumps(safe_headers, ensure_ascii=False),
                now(),
            ),
        )
        connection.commit()
    return Response(status_code=204)
