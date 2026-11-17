from __future__ import annotations

import math
import secrets
import urllib.parse
from pathlib import Path
from typing import Any

from ..auth_session import (
    AuthSession,
    authenticate,
    authenticate_with_credentials,
    get_auth_profile,
)
from ..config import settings
from ..schemas.finding import Finding
from .base import BaseAdapter


IGNORED_COOKIE_NAMES = {"security", "csrftoken", "csrf_token", "x-csrf-token"}
RATE_LIMIT_MARKERS = (
    "too many",
    "rate limit",
    "locked",
    "temporarily blocked",
    "captcha",
    "try again later",
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _unique_cookie_values(sessions: list[AuthSession]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for session in sessions:
        for name, value in session.cookies.items():
            if name.lower() in IGNORED_COOKIE_NAMES:
                continue
            values.setdefault(name, []).append(value)
    return values


class AuthAnalysisAdapter(BaseAdapter):
    name = "auth_analysis"
    tool_version = "builtin-1"

    def available(self) -> bool:
        return True

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        auth_ref = str(options.get("auth_ref") or "")
        if not auth_ref:
            return []
        level = str(options.get("validation_level") or "safe")
        if level == "off":
            return []
        profile = get_auth_profile(auth_ref)
        if profile.type != "form":
            return []
        sessions = self._sessions(auth_ref, profile.session_samples)
        findings = self._session_findings(target_or_input, sessions, options)
        if level == "deep":
            findings.extend(self._credential_findings(auth_ref, profile, options))
            if profile.rate_limit_probe:
                findings.extend(self._rate_limit_findings(auth_ref, options))
        return self._filter_findings(findings, options)

    def _sessions(self, auth_ref: str, count: int) -> list[AuthSession]:
        sessions: list[AuthSession] = []
        for sample in range(max(1, min(5, count))):
            self._check_cancel()
            try:
                session = authenticate(auth_ref, sample=sample)
            except Exception:
                continue
            if session.authenticated:
                sessions.append(session)
        return sessions

    def _session_findings(
        self,
        target: Any,
        sessions: list[AuthSession],
        options: dict[str, Any],
    ) -> list[Finding]:
        if not sessions:
            return []
        target_text = str(target)
        parsed_target = urllib.parse.urlparse(target_text)
        target_host = parsed_target.hostname or target_text
        target_port = parsed_target.port
        output: list[Finding] = []
        values = _unique_cookie_values(sessions)
        weak_names = []
        for name, samples in values.items():
            distinct = len(set(samples))
            minimum_length = min(len(item) for item in samples)
            minimum_entropy = min(_entropy(item) for item in samples)
            if distinct == 1 or minimum_length < 16 or minimum_entropy < 3.0:
                weak_names.append(
                    {
                        "cookie": name,
                        "samples": len(samples),
                        "distinct": distinct,
                        "min_length": minimum_length,
                        "min_entropy": round(minimum_entropy, 3),
                    }
                )
        if weak_names:
            output.append(
                Finding(
                    source=self.name,
                    host=target_host,
                    port=target_port,
                    url=target_text,
                    vuln_type="weak_session_id",
                    severity="medium",
                    evidence={"cookies": weak_names, "samples": len(sessions)},
                )
            )
        fixed = []
        for session in sessions:
            for name, value in session.pre_login_cookies.items():
                if (
                    name.lower() not in IGNORED_COOKIE_NAMES
                    and session.cookies.get(name) == value
                ):
                    fixed.append(name)
        if fixed:
            output.append(
                Finding(
                    source=self.name,
                    host=target_host,
                    port=target_port,
                    url=target_text,
                    vuln_type="session_fixation",
                    severity="high",
                    evidence={"cookies": sorted(set(fixed)), "samples": len(sessions)},
                )
            )
        return self._filter_findings(output, options)

    def _credential_findings(self, auth_ref, profile, options) -> list[Finding]:
        path = Path(profile.weak_credentials_file or settings.weak_credentials_file)
        if not path.exists():
            return []
        pairs = self._read_credentials(path)
        output: list[Finding] = []
        parsed = urllib.parse.urlparse(profile.login_url)
        for username, password in pairs[:8]:
            self._check_cancel()
            try:
                session = authenticate_with_credentials(
                    auth_ref,
                    username,
                    password,
                )
            except Exception:
                continue
            if not session.authenticated:
                continue
            output.append(
                Finding(
                    source=self.name,
                    host=parsed.hostname or "",
                    port=parsed.port,
                    url=profile.login_url,
                    vuln_type="default_credentials",
                    severity="high",
                    evidence={
                        "username": username,
                        "credential_source": "configured_weak_dictionary",
                    },
                )
            )
            break
        return self._filter_findings(output, options)

    def _rate_limit_findings(self, auth_ref: str, options) -> list[Finding]:
        username = f"scanner_probe_{secrets.token_hex(4)}"
        outcomes = []
        for index in range(3):
            self._check_cancel()
            try:
                session = authenticate_with_credentials(
                    auth_ref,
                    username,
                    f"invalid-{secrets.token_hex(8)}",
                    sample=index,
                )
            except Exception as exc:
                outcomes.append({"error": type(exc).__name__})
                continue
            body = session.body_excerpt.lower()
            limited = (
                session.status_code in {423, 429}
                or bool(session.response_headers.get("retry-after"))
                or any(marker in body for marker in RATE_LIMIT_MARKERS)
            )
            outcomes.append(
                {
                    "status": session.status_code,
                    "latency_ms": session.latency_ms,
                    "limited": limited,
                }
            )
            if limited:
                return []
        if sum(1 for item in outcomes if item.get("status") is not None) < 2:
            return []
        return [
            Finding(
                source=self.name,
                host=urllib.parse.urlparse(
                    get_auth_profile(auth_ref).login_url
                ).hostname
                or "",
                port=urllib.parse.urlparse(
                    get_auth_profile(auth_ref).login_url
                ).port,
                url=get_auth_profile(auth_ref).login_url,
                vuln_type="brute_force",
                severity="low",
                evidence={
                    "attempts": len(outcomes),
                    "mitigation_observed": False,
                    "outcomes": outcomes,
                },
            )
        ]

    @staticmethod
    def _read_credentials(path: Path) -> list[tuple[str, str]]:
        output = []
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            separator = ":" if ":" in value else ","
            if separator not in value:
                continue
            username, password = value.split(separator, 1)
            if username.strip() and password.strip():
                output.append((username.strip(), password.strip()))
        return output
