from __future__ import annotations

import json
import os
import time
import urllib.parse
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Iterator, Literal

import httpx
from pydantic import BaseModel, Field

from .guard import authorization_entry, load_authorizations


class AuthConfigError(ValueError):
    pass


class _FieldParser(HTMLParser):
    def __init__(self, field_name: str) -> None:
        super().__init__()
        self.field_name = field_name.lower()
        self.value = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input" or self.value:
            return
        values = {key.lower(): value or "" for key, value in attrs}
        if values.get("name", "").lower() == self.field_name:
            self.value = values.get("value", "")


@dataclass
class _DiscoveredForm:
    action: str = ""
    method: str = "post"
    fields: dict[str, str] = field(default_factory=dict)
    username_field: str = ""
    password_field: str = ""
    submit_field: str = ""
    submit_value: str = ""


class _LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.current: _DiscoveredForm | None = None
        self.forms: list[_DiscoveredForm] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "form":
            self.current = _DiscoveredForm(
                action=values.get("action", ""),
                method=(values.get("method") or "post").lower(),
            )
            return
        if tag not in {"input", "button"} or self.current is None:
            return
        name = values.get("name", "").strip()
        input_type = (values.get("type") or "text").lower()
        if input_type == "password" and not self.current.password_field:
            self.current.password_field = name
        elif (
            input_type in {"text", "email", "tel", "username"}
            and name
            and not self.current.username_field
        ):
            self.current.username_field = name
        elif input_type in {"submit", "button"} and name:
            self.current.submit_field = name
            self.current.submit_value = values.get("value", "")
        if name and input_type not in {"submit", "button", "file"}:
            self.current.fields[name] = values.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._finish_current()

    def close(self) -> None:
        self._finish_current()
        super().close()

    def _finish_current(self) -> None:
        if self.current is None:
            return
        self.forms.append(self.current)
        self.current = None


class AuthProfile(BaseModel):
    type: Literal[
        "none",
        "auto",
        "form",
        "json",
        "cookie",
        "bearer",
        "basic",
    ] = "none"
    label: str = ""
    target_hint: str = ""
    target_hosts: list[str] = Field(default_factory=list)
    login_url: str = ""
    verification_url: str = ""
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    username_env: str = ""
    password_env: str = ""
    username: str = ""
    csrf_field: str = ""
    submit_field: str = ""
    submit_value: str = ""
    extra_fields: dict[str, str] = Field(default_factory=dict)
    headers_env: str = ""
    cookie_env: str = ""
    token_env: str = ""
    token_json_path: str = ""
    token_header: str = "Authorization"
    token_prefix: str = "Bearer "
    token_cookie_name: str = ""
    basic_username_env: str = ""
    basic_password_env: str = ""
    logged_in_indicator: str = ""
    logged_out_indicator: str = ""
    success_url_contains: str = ""
    weak_credentials_file: str = ""
    safe_path_denylist: list[str] = Field(default_factory=list)
    active_scan_exclude: list[str] = Field(default_factory=list)
    session_samples: int = 3
    rate_limit_probe: bool = False

    def applies_to(self, target: str) -> bool:
        host = urllib.parse.urlparse(
            target if "://" in target else f"//{target}"
        ).hostname or target
        host = host.lower()
        allowed = [item.lower().lstrip(".") for item in self.target_hosts if item]
        if allowed:
            return any(
                host == item
                or (item.startswith("*.") and host.endswith(item[1:]))
                for item in allowed
            )
        if self.login_url:
            login_host = urllib.parse.urlparse(self.login_url).hostname or ""
            return host == login_host.lower()
        return True

    def public_summary(self, auth_ref: str) -> dict[str, Any]:
        return {
            "auth_ref": auth_ref,
            "label": self.label or auth_ref,
            "type": self.type,
            "target_hint": self.target_hint,
            "target_hosts": self.target_hosts,
            "verification_url": self.verification_url,
        }


@dataclass
class AuthSession:
    authenticated: bool = False
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    pre_login_cookies: dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    verification_url: str = ""
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    latency_ms: int | None = None
    body_excerpt: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def cookie_header(self) -> str:
        return "; ".join(f"{name}={value}" for name, value in self.cookies.items())

    def request_headers(self) -> dict[str, str]:
        output = dict(self.headers)
        if self.cookies:
            output["Cookie"] = self.cookie_header
        return output

    def metrics(self) -> dict[str, Any]:
        return {
            "authenticated": self.authenticated,
            "cookie_names": sorted(self.cookies),
            "has_cookie_session": bool(self.cookies),
            "has_authorization_header": "Authorization" in self.headers,
            "login_url": self.login_url,
            "verification_url": self.verification_url,
            "status_code": self.status_code,
            "latency_ms": self.latency_ms,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class AuthCredentialOverride:
    auth_ref: str
    profile: AuthProfile
    username: str
    password: str = field(repr=False)


_auth_override: ContextVar[AuthCredentialOverride | None] = ContextVar(
    "auth_credential_override",
    default=None,
)


@contextmanager
def use_auth_credentials(
    override: AuthCredentialOverride,
) -> Iterator[None]:
    token = _auth_override.set(override)
    try:
        yield
    finally:
        _auth_override.reset(token)


def _current_override(auth_ref: str) -> AuthCredentialOverride | None:
    override = _auth_override.get()
    if override is None or override.auth_ref != auth_ref:
        return None
    return override


def _entry_profile(auth_ref: str) -> tuple[AuthProfile, dict[str, Any]]:
    entry = authorization_entry(auth_ref)
    raw = entry.get("authentication") or {"type": "none"}
    if not isinstance(raw, dict):
        raise AuthConfigError("authentication must be a mapping")
    try:
        return AuthProfile.model_validate(raw), entry
    except Exception as exc:
        raise AuthConfigError(f"invalid authentication profile: {exc}") from exc


def get_auth_profile(auth_ref: str) -> AuthProfile:
    override = _current_override(auth_ref)
    if override is not None:
        return override.profile
    if (auth_ref or "").strip().lower() in {"", "none", "custom", "unauthenticated"}:
        return AuthProfile(type="none", label="No authentication")
    return _entry_profile(auth_ref)[0]


def list_auth_profiles() -> list[dict[str, Any]]:
    payload = load_authorizations()
    refs = payload.get("auth_refs") or {}
    if not isinstance(refs, dict):
        return []
    output = []
    for auth_ref, entry in refs.items():
        if not isinstance(entry, dict):
            continue
        try:
            profile = AuthProfile.model_validate(
                entry.get("authentication") or {"type": "none"}
            )
        except Exception:
            continue
        summary = profile.public_summary(str(auth_ref))
        summary["scope"] = entry.get("scope") or []
        output.append(summary)
    return sorted(
        output,
        key=lambda item: (
            not str(item["auth_ref"]).startswith("local-"),
            str(item["auth_ref"]),
        ),
    )


def _env_value(name: str, fallback: str = "") -> str:
    if not name:
        return fallback
    return os.getenv(name, fallback)


def _cookie_dict(header: str) -> dict[str, str]:
    output: dict[str, str] = {}
    for item in header.split(";"):
        if "=" not in item:
            continue
        name, value = item.split("=", 1)
        if name.strip():
            output[name.strip()] = value.strip()
    return output


def _headers_from_env(name: str) -> dict[str, str]:
    if not name:
        return {}
    raw = os.getenv(name, "").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthConfigError(f"{name} must contain a JSON object") from exc
    if not isinstance(payload, dict):
        raise AuthConfigError(f"{name} must contain a JSON object")
    return {str(key): str(value) for key, value in payload.items()}


def _json_path(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not part:
            continue
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _client(
    session: AuthSession,
    profile: AuthProfile,
    *,
    auth: tuple[str, str] | None = None,
) -> httpx.Client:
    return httpx.Client(
        follow_redirects=True,
        timeout=None,
        headers={**session.headers, **_headers_from_env(profile.headers_env)},
        cookies=session.cookies,
        auth=auth,
    )


def _verified(
    client: httpx.Client,
    profile: AuthProfile,
    response: httpx.Response,
) -> bool:
    if profile.success_url_contains and profile.success_url_contains.lower() not in str(
        response.url
    ).lower():
        return False
    if profile.verification_url:
        verification = client.get(profile.verification_url)
        verification.raise_for_status()
        verify_text = verification.text.lower()
        if (
            profile.logged_in_indicator
            and profile.logged_in_indicator.lower() not in verify_text
        ):
            return False
        if (
            profile.logged_out_indicator
            and profile.logged_out_indicator.lower() in verify_text
        ):
            return False
        return True
    text = response.text.lower()
    if profile.logged_in_indicator and profile.logged_in_indicator.lower() not in text:
        return False
    if profile.logged_out_indicator and profile.logged_out_indicator.lower() in text:
        return False
    return True


def _discover_login_form(response: httpx.Response) -> _DiscoveredForm:
    parser = _LoginFormParser()
    parser.feed(response.text)
    parser.close()
    for form in parser.forms:
        if form.password_field:
            return form
    raise AuthConfigError("could not find a login form with a password field")


def _authenticate_form(
    profile: AuthProfile,
    sample: int = 0,
    username_override: str | None = None,
    password_override: str | None = None,
) -> AuthSession:
    if not profile.login_url:
        raise AuthConfigError("form authentication requires login_url")
    username = username_override or _env_value(profile.username_env, profile.username)
    password = password_override or _env_value(profile.password_env)
    if not username or not password:
        raise AuthConfigError("form credentials are not configured")
    with httpx.Client(
        follow_redirects=True,
        timeout=None,
        headers=_headers_from_env(profile.headers_env),
    ) as initial:
        page = initial.get(profile.login_url)
        page.raise_for_status()
        pre_cookies = {
            str(cookie.name): str(cookie.value) for cookie in initial.cookies.jar
        }
        login_url = profile.login_url
        method = profile.method
        username_field = profile.username_field
        password_field = profile.password_field
        submit_field = profile.submit_field
        submit_value = profile.submit_value
        payload = dict(profile.extra_fields)
        if profile.type == "auto":
            form = _discover_login_form(page)
            login_url = urllib.parse.urljoin(
                str(page.url),
                form.action or str(page.url),
            )
            method = form.method
            username_field = form.username_field
            password_field = form.password_field
            submit_field = form.submit_field
            submit_value = form.submit_value
            payload.update(form.fields)
        if not username_field or not password_field:
            raise AuthConfigError("login form username or password field is missing")
        token = ""
        if profile.csrf_field:
            parser = _FieldParser(profile.csrf_field)
            parser.feed(page.text)
            token = parser.value
        payload[username_field] = username
        payload[password_field] = password
        if submit_field:
            payload[submit_field] = submit_value or "1"
        if profile.csrf_field and token:
            payload[profile.csrf_field] = token
        started = time.monotonic()
        response = initial.request(
            method.upper(),
            login_url,
            data=payload,
        )
        latency_ms = int((time.monotonic() - started) * 1000)
        if response.status_code != 429:
            response.raise_for_status()
        if not _verified(initial, profile, response):
            return AuthSession(
                authenticated=False,
                pre_login_cookies=pre_cookies,
                login_url=login_url,
                verification_url=profile.verification_url,
                status_code=response.status_code,
                response_headers=dict(response.headers),
                latency_ms=latency_ms,
                body_excerpt=response.text[:2000],
                warnings=[f"login_verification_failed_sample_{sample}"],
            )
        cookies = {
            str(cookie.name): str(cookie.value) for cookie in initial.cookies.jar
        }
        return AuthSession(
            authenticated=True,
            cookies=cookies,
            headers=_headers_from_env(profile.headers_env),
            pre_login_cookies=pre_cookies,
            login_url=login_url,
            verification_url=profile.verification_url,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            latency_ms=latency_ms,
            body_excerpt=response.text[:2000],
        )


def _authenticate_json(
    profile: AuthProfile,
    sample: int = 0,
    username_override: str | None = None,
    password_override: str | None = None,
) -> AuthSession:
    if not profile.login_url:
        raise AuthConfigError("json authentication requires login_url")
    username = username_override or _env_value(profile.username_env, profile.username)
    password = password_override or _env_value(profile.password_env)
    if not username or not password:
        raise AuthConfigError("json credentials are not configured")
    payload = dict(profile.extra_fields)
    payload[profile.username_field] = username
    payload[profile.password_field] = password
    started = time.monotonic()
    with httpx.Client(
        follow_redirects=True,
        timeout=None,
        headers=_headers_from_env(profile.headers_env),
    ) as client:
        response = client.request(
            profile.method.upper(),
            profile.login_url,
            json=payload,
        )
        latency_ms = int((time.monotonic() - started) * 1000)
        response.raise_for_status()
        try:
            body = response.json()
        except ValueError as exc:
            raise AuthConfigError("json authentication response is not JSON") from exc
        token = _json_path(body, profile.token_json_path) if profile.token_json_path else ""
        token = str(token or "").strip()
        if not token:
            raise AuthConfigError("json authentication did not return a token")
        cookies = {
            str(cookie.name): str(cookie.value) for cookie in client.cookies.jar
        }
        if profile.token_cookie_name:
            cookies.setdefault(profile.token_cookie_name, token)
        headers = {
            **_headers_from_env(profile.headers_env),
            profile.token_header or "Authorization": f"{profile.token_prefix}{token}",
        }
        session = AuthSession(
            authenticated=True,
            cookies=cookies,
            headers=headers,
            login_url=profile.login_url,
            verification_url=profile.verification_url,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            latency_ms=latency_ms,
            body_excerpt=response.text[:2000],
        )
        if profile.verification_url:
            with _client(session, profile) as verification_client:
                verification = verification_client.get(profile.verification_url)
                verification.raise_for_status()
                verify_text = verification.text.lower()
                login_ok = (
                    not profile.logged_in_indicator
                    or profile.logged_in_indicator.lower() in verify_text
                )
                logout_absent = (
                    not profile.logged_out_indicator
                    or profile.logged_out_indicator.lower() not in verify_text
                )
                if not (login_ok and logout_absent):
                    session.authenticated = False
                    session.warnings.append(
                        f"login_verification_failed_sample_{sample}"
                    )
        return session


def authenticate(auth_ref: str, *, sample: int = 0) -> AuthSession:
    profile = get_auth_profile(auth_ref)
    override = _current_override(auth_ref)
    if profile.type == "none":
        return AuthSession(authenticated=True, warnings=["authentication_not_required"])
    if profile.type in {"auto", "form"}:
        return _authenticate_form(
            profile,
            sample=sample,
            username_override=override.username if override else None,
            password_override=override.password if override else None,
        )
    if profile.type == "json":
        return _authenticate_json(
            profile,
            sample=sample,
            username_override=override.username if override else None,
            password_override=override.password if override else None,
        )
    if profile.type == "cookie":
        cookie_header = _env_value(profile.cookie_env)
        if not cookie_header:
            raise AuthConfigError("cookie authentication requires a populated cookie_env")
        session = AuthSession(
            authenticated=True,
            cookies=_cookie_dict(cookie_header),
            headers=_headers_from_env(profile.headers_env),
            login_url=profile.login_url,
            verification_url=profile.verification_url,
        )
        if profile.verification_url:
            with _client(session, profile) as client:
                response = client.get(profile.verification_url)
                response.raise_for_status()
                session.authenticated = _verified(client, profile, response)
        return session
    if profile.type == "bearer":
        token = _env_value(profile.token_env)
        if not token:
            raise AuthConfigError("bearer authentication requires a populated token_env")
        session = AuthSession(
            authenticated=True,
            headers={"Authorization": f"Bearer {token}", **_headers_from_env(profile.headers_env)},
            login_url=profile.login_url,
            verification_url=profile.verification_url,
        )
        if profile.verification_url:
            with _client(session, profile) as client:
                response = client.get(profile.verification_url)
                response.raise_for_status()
                session.authenticated = _verified(client, profile, response)
        return session
    if profile.type == "basic":
        username = _env_value(profile.basic_username_env, profile.username)
        password = _env_value(profile.basic_password_env)
        if not username or not password:
            raise AuthConfigError("basic authentication credentials are not configured")
        session = AuthSession(
            authenticated=True,
            headers=_headers_from_env(profile.headers_env),
            login_url=profile.login_url,
            verification_url=profile.verification_url,
        )
        if profile.verification_url:
            with _client(session, profile, auth=(username, password)) as client:
                response = client.get(profile.verification_url)
                response.raise_for_status()
                session.authenticated = _verified(client, profile, response)
        return session
    raise AuthConfigError(f"unsupported authentication type: {profile.type}")


def authenticate_with_credentials(
    auth_ref: str,
    username: str,
    password: str,
    *,
    sample: int = 0,
) -> AuthSession:
    profile = get_auth_profile(auth_ref)
    if profile.type not in {"auto", "form"}:
        raise AuthConfigError("credential probing requires form authentication")
    return _authenticate_form(
        profile,
        sample=sample,
        username_override=username,
        password_override=password,
    )
