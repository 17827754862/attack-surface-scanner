from __future__ import annotations

import json

import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from ..config import settings
from ..db import SessionLocal, User
from ..security import decode_token


router = APIRouter(prefix="/api/tasks", tags=["events"])


def format_sse(payload: str) -> str:
    return f"data: {payload}\n\n"


@router.get("/{task_id}/events")
async def task_events(task_id: str, request: Request):
    token = request.query_params.get("token", "")
    if not token:
        raise HTTPException(status_code=401, detail="token required")
    username = decode_token(token)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
    finally:
        db.close()
    if user is None:
        raise HTTPException(status_code=401, detail="user not found")

    client = aioredis.from_url(settings.redis_url, decode_responses=True)
    pubsub = client.pubsub()
    await pubsub.subscribe(f"task:{task_id}:events")

    async def stream():
        try:
            yield ": connected\n\n"
            async for message in pubsub.listen():
                if await request.is_disconnected():
                    break
                if message.get("type") == "message":
                    yield format_sse(str(message.get("data")))
        finally:
            await pubsub.unsubscribe(f"task:{task_id}:events")
            await pubsub.close()
            await client.close()

    return StreamingResponse(stream(), media_type="text/event-stream")
