from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..ai_config import decrypt_api_key, load_ai_config, save_ai_config
from ..ai_service import test_ai_connection
from ..db import AIConfig, AuditLog, User, get_db
from ..schemas.ai import AIConfigResponse, AIConfigUpdate, AITestRequest
from ..security import get_current_user


router = APIRouter(prefix="/api/ai", tags=["ai"])


def _response(config) -> AIConfigResponse:
    return AIConfigResponse(
        enabled=config.enabled,
        base_url=config.base_url,
        model=config.model,
        api_key_configured=bool(config.api_key),
        source=config.source,
    )


@router.get("/config", response_model=AIConfigResponse)
def get_ai_config(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> AIConfigResponse:
    return _response(load_ai_config(db))


@router.put("/config", response_model=AIConfigResponse)
def update_ai_config(
    payload: AIConfigUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> AIConfigResponse:
    config = save_ai_config(
        db,
        enabled=payload.enabled,
        base_url=payload.base_url,
        model=payload.model,
        api_key=payload.api_key,
    )
    db.add(
        AuditLog(
            username=user.username,
            action="ai.config.update",
            detail={
                "enabled": config.enabled,
                "base_url": config.base_url,
                "model": config.model,
                "api_key_configured": bool(config.api_key),
            },
        )
    )
    db.commit()
    return _response(config)


@router.post("/test")
def test_ai(
    payload: AITestRequest,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    saved = load_ai_config(db)
    api_key = payload.api_key
    if api_key is None:
        row = db.get(AIConfig, 1)
        api_key = decrypt_api_key(row.api_key_ciphertext) if row else saved.api_key
    config = saved.__class__(
        enabled=payload.enabled,
        base_url=payload.base_url or saved.base_url,
        api_key=api_key or "",
        model=payload.model or saved.model,
        source="request",
    )
    try:
        return test_ai_connection(config)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI connection failed: {exc}") from exc
