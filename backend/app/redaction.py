from __future__ import annotations

import re
from typing import Any


SENSITIVE_KEY = re.compile(
    r"(password|passwd|token|cookie|authorization|api[_-]?key|secret)",
    flags=re.IGNORECASE,
)
SECRET_PAIR = re.compile(
    r"(?i)\b(password|passwd|token|cookie|api[_-]?key|secret)=([^&\s]+)"
)
BEARER_VALUE = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._~+/=-]+)"
)
URL_USERINFO = re.compile(r"(?i)(https?://[^:/@\s]+:)([^@\s]+)(@)")


def redact_text(value: str) -> str:
    redacted = SECRET_PAIR.sub(lambda match: f"{match.group(1)}=***", value)
    redacted = BEARER_VALUE.sub(lambda match: f"{match.group(1)}***", redacted)
    return URL_USERINFO.sub(lambda match: f"{match.group(1)}***{match.group(3)}", redacted)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if SENSITIVE_KEY.search(str(key)):
                output[key] = "***"
            else:
                output[key] = redact(item)
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value
