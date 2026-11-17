from __future__ import annotations

from pydantic import BaseModel


class AIConfigUpdate(BaseModel):
    enabled: bool
    base_url: str = ""
    model: str = "deepseek-chat"
    api_key: str | None = None


class AIConfigResponse(BaseModel):
    enabled: bool
    base_url: str
    model: str
    api_key_configured: bool
    source: str


class AITestRequest(BaseModel):
    enabled: bool = True
    base_url: str = ""
    model: str = "deepseek-chat"
    api_key: str | None = None
