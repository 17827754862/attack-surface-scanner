from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class CustomAuthCreate(BaseModel):
    type: Literal["auto", "form", "json"] = "auto"
    login_url: str
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=2048, repr=False)
    verification_url: str = ""
    username_field: str = ""
    password_field: str = ""
    submit_field: str = ""
    submit_value: str = ""
    token_json_path: str = "authentication.token"
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "
    token_cookie_name: str = ""
    logged_in_indicator: str = ""
    logged_out_indicator: str = ""
    success_url_contains: str = ""


class TaskCreate(BaseModel):
    target: str
    auth_ref: str = "none"
    max_rps: int = Field(default=5)
    mode: Literal["passive", "active", "full"] = "active"
    validation_level: Literal["off", "safe", "deep"] = "safe"
    oast_enabled: bool = False
    authorization_confirmed: bool = False
    tool_profile: Literal[
        "full_agent",
        "nuclei",
        "zap_wapiti_nuclei",
        "validation_only",
    ] = "full_agent"
    custom_auth: CustomAuthCreate | None = None

    @model_validator(mode="after")
    def validate_probe_options(self) -> "TaskCreate":
        if self.oast_enabled and self.validation_level != "deep":
            raise ValueError("oast_enabled requires validation_level=deep")
        return self


class TaskResponse(BaseModel):
    id: str
    target: str
    auth_ref: str = "none"
    status: str
    mode: str
    tool_profile: str = "full_agent"
    node_status: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    blocked_targets: list[str] = Field(default_factory=list)
    auth_metrics: dict[str, Any] = Field(default_factory=dict)
    validation_level: str = "safe"
    oast_enabled: bool = False
    llm_summary: str | None = None
    risk_groups: list[dict[str, Any]] = Field(default_factory=list)
    memory_context: dict[str, Any] = Field(default_factory=dict)
    findings_count: int = 0
    routing_mode: str = "auto"
    routing_reason: str = ""
    routing_confidence: int = 0
    next_scan_node: str = ""
    completed_scan_nodes: list[str] = Field(default_factory=list)
    scan_decisions: list[dict[str, Any]] = Field(default_factory=list)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TraceEntry(BaseModel):
    node_name: str
    tool_name: str = ""
    started_at: str = ""
    finished_at: str = ""
    status: str = ""
    output_summary: str = ""
    error: str | None = None
