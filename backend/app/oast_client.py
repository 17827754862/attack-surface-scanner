from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from .config import settings


class OastError(RuntimeError):
    pass


@dataclass(frozen=True)
class OastToken:
    token: str
    callback_url: str


class OastClient:
    def __init__(
        self,
        base_url: str | None = None,
        secret: str | None = None,
    ) -> None:
        self.base_url = (base_url or settings.oast_url).rstrip("/")
        self.secret = secret or settings.oast_secret

    def _headers(self) -> dict[str, str]:
        return {"X-OAST-Secret": self.secret}

    def available(self) -> bool:
        try:
            response = httpx.get(f"{self.base_url}/health", timeout=None)
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    def create_token(self, label: str) -> OastToken:
        response = httpx.post(
            f"{self.base_url}/api/tokens",
            headers=self._headers(),
            json={"label": label},
            timeout=None,
        )
        response.raise_for_status()
        payload = response.json()
        token = str(payload.get("token") or "")
        callback_url = str(payload.get("callback_url") or "")
        if not token or not callback_url:
            raise OastError("callback service returned an incomplete token")
        return OastToken(token=token, callback_url=callback_url)

    def hits(self, token: OastToken) -> list[dict[str, Any]]:
        response = httpx.get(
            f"{self.base_url}/api/tokens/{token.token}",
            headers=self._headers(),
            timeout=None,
        )
        response.raise_for_status()
        payload = response.json()
        rows = payload.get("hits") or []
        return [item for item in rows if isinstance(item, dict)]

    def wait_for_hit(
        self,
        token: OastToken,
        *,
        poll_interval: float = 0.5,
        should_stop: Callable[[], bool] | None = None,
    ) -> dict[str, Any] | None:
        while True:
            if should_stop and should_stop():
                return None
            rows = self.hits(token)
            if rows:
                return rows[0]
            time.sleep(poll_interval)
