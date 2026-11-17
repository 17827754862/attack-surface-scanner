from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .config import settings
from .db import AIConfig


@dataclass(frozen=True)
class AIRuntimeConfig:
    enabled: bool
    base_url: str
    api_key: str
    model: str
    source: str


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.jwt_secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_api_key(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_api_key(value: str) -> str:
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def load_ai_config(db: Session | None = None) -> AIRuntimeConfig:
    row = db.get(AIConfig, 1) if db is not None else None
    if row is not None:
        return AIRuntimeConfig(
            enabled=bool(row.enabled),
            base_url=row.base_url,
            api_key=decrypt_api_key(row.api_key_ciphertext),
            model=row.model,
            source="database",
        )
    return AIRuntimeConfig(
        enabled=bool(settings.llm_enabled),
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        model=settings.llm_model,
        source="environment",
    )


def save_ai_config(
    db: Session,
    *,
    enabled: bool,
    base_url: str,
    model: str,
    api_key: str | None,
) -> AIRuntimeConfig:
    row = db.get(AIConfig, 1)
    if row is None:
        initial_key = settings.llm_api_key if api_key is None else api_key
        row = AIConfig(
            id=1,
            api_key_ciphertext=encrypt_api_key(initial_key.strip()),
        )
        db.add(row)
    row.enabled = enabled
    row.base_url = base_url.strip()
    row.model = model.strip() or "deepseek-chat"
    if api_key is not None:
        row.api_key_ciphertext = encrypt_api_key(api_key.strip())
    db.commit()
    db.refresh(row)
    return load_ai_config(db)
