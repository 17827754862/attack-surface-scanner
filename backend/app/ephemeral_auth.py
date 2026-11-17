from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


class EphemeralAuthError(ValueError):
    pass


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.jwt_secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def seal_auth_payload(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _fernet().encrypt(raw).decode("ascii")


def open_auth_payload(token: str) -> dict[str, Any]:
    try:
        raw = _fernet().decrypt(token.encode("ascii"))
    except (InvalidToken, ValueError) as exc:
        raise EphemeralAuthError("temporary authentication payload is invalid") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EphemeralAuthError("temporary authentication payload is malformed") from exc
    if not isinstance(payload, dict):
        raise EphemeralAuthError("temporary authentication payload must be an object")
    return payload
