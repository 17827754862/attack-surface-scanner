from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    source: str
    host: str
    url: str | None = None
    port: int | None = None
    vuln_type: str
    severity: Severity = "info"
    evidence: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    also_reported_by: list[str] = Field(default_factory=list)
    fingerprint: str = ""
    score: float = 0.0
    confidence: int = 0
    evidence_hash: str = ""
    playbook: str | None = None

    @model_validator(mode="after")
    def ensure_fingerprint(self) -> "Finding":
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        if not self.evidence_hash:
            self.evidence_hash = self.compute_evidence_hash()
        return self

    def compute_fingerprint(self) -> str:
        payload = {
            "host": self.host.lower(),
            "port": self.port,
            "url": self.url or "",
            "vuln_type": self.vuln_type.lower(),
        }
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:32]

    def compute_evidence_hash(self) -> str:
        encoded = json.dumps(
            self.evidence,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
