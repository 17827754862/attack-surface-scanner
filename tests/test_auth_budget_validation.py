from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.adapters.active_validation import ActiveValidationAdapter, SQL_ERROR_PATTERNS
from app.adapters.auth_analysis import AuthAnalysisAdapter
from app.auth_session import (
    AuthCredentialOverride,
    AuthProfile,
    AuthSession,
    authenticate,
    list_auth_profiles,
    use_auth_credentials,
)
from app.config import settings


def _scope_options() -> dict:
    return {
        "scope": ["dvwa"],
        "allowed_cidrs": ["172.16.0.0/12"],
        "blocked_targets": [],
        "max_rps": 20,
        "validation_max_pages": 4,
        "validation_max_parameters": 20,
        "validation_max_requests": 20,
        "validation_level": "safe",
        "safe_path_denylist": [],
        "active_scan_exclude": [],
    }


@pytest.fixture(autouse=True)
def allow_test_scope(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "app.adapters.base.validate_scope",
        lambda candidate, scope, cidrs: SimpleNamespace(host="dvwa"),
    )
    monkeypatch.setattr(
        "app.adapters.active_validation.validate_scope",
        lambda candidate, scope, cidrs: SimpleNamespace(host="dvwa"),
    )


def test_auth_profile_login_and_safe_summary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    auth_file = tmp_path / "auth.yaml"
    auth_file.write_text(
        """
auth_refs:
  portal:
    authentication:
      type: form
      label: Portal
      target_hint: http://portal
      target_hosts: [portal]
      login_url: http://portal/login
      username_env: PORTAL_USER
      password_env: PORTAL_PASSWORD
      username_field: user
      password_field: pass
      csrf_field: csrf
      submit_field: submit
      submit_value: Login
      logged_in_indicator: Logout
    scope: [portal]
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "authorization_file", str(auth_file))
    monkeypatch.setenv("PORTAL_USER", "alice")
    monkeypatch.setenv("PORTAL_PASSWORD", "secret")

    class Cookies:
        jar = [SimpleNamespace(name="sid", value="abcdefghijklmnopqrstuvwxyz")]

    class Client:
        cookies = Cookies()

        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def get(self, _url):
            return SimpleNamespace(
                text="<input name='csrf' value='token-1'>",
                raise_for_status=lambda: None,
            )
        def request(self, _method, _url, data):
            assert data["csrf"] == "token-1"
            return SimpleNamespace(
                text="<a>Logout</a>",
                url="http://portal/home",
                status_code=200,
                headers={},
                raise_for_status=lambda: None,
            )

    monkeypatch.setattr("app.auth_session.httpx.Client", lambda **_kwargs: Client())
    session = authenticate("portal")
    assert session.authenticated
    assert session.cookie_header == "sid=abcdefghijklmnopqrstuvwxyz"
    summaries = list_auth_profiles()
    assert summaries[0]["auth_ref"] == "portal"
    assert "login_url" not in summaries[0]
    assert AuthProfile(
        type="form",
        target_hosts=["portal"],
        login_url="http://portal/login",
    ).applies_to("http://portal/")


def test_json_auth_adds_bearer_token_and_verifies_session(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    auth_file = tmp_path / "auth.yaml"
    auth_file.write_text(
        """
auth_refs:
  juice:
    authentication:
      type: json
      label: Juice Shop
      target_hosts: [juice-shop]
      login_url: http://juice-shop:3000/rest/user/login
      verification_url: http://juice-shop:3000/rest/user/whoami
      username_field: email
      password_field: password
      username_env: JUICE_EMAIL
      password_env: JUICE_PASSWORD
      token_json_path: authentication.token
      token_header: Authorization
      token_prefix: "Bearer "
      token_cookie_name: token
      logged_in_indicator: 1@qq.com
    scope: [juice-shop]
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "authorization_file", str(auth_file))
    monkeypatch.setenv("JUICE_EMAIL", "1@qq.com")
    monkeypatch.setenv("JUICE_PASSWORD", "test-password")
    requests: list[tuple[str, str, dict]] = []

    class CookieStore(dict):
        jar: list[SimpleNamespace] = []

    class Client:
        def __init__(self, **kwargs):
            self.headers = kwargs.get("headers", {})
            self.auth = kwargs.get("auth")
            self.cookies = CookieStore(kwargs.get("cookies", {}))

        def __enter__(self): return self
        def __exit__(self, *_args): return None

        def request(self, method, url, **kwargs):
            requests.append((method, url, kwargs))
            assert kwargs["json"] == {
                "email": "1@qq.com",
                "password": "test-password",
            }
            return httpx.Response(
                200,
                json={"authentication": {"token": "test-token"}},
                request=httpx.Request(method, url),
            )

        def get(self, url):
            requests.append(("GET", url, {}))
            assert self.headers["Authorization"] == "Bearer test-token"
            assert self.cookies["token"] == "test-token"
            return httpx.Response(
                200,
                json={"user": {"email": "1@qq.com"}},
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr("app.auth_session.httpx.Client", lambda **kwargs: Client(**kwargs))
    session = authenticate("juice")

    assert session.authenticated
    assert session.headers["Authorization"] == "Bearer test-token"
    assert session.cookies["token"] == "test-token"
    assert [item[1] for item in requests] == [
        "http://juice-shop:3000/rest/user/login",
        "http://juice-shop:3000/rest/user/whoami",
    ]


def test_auto_form_auth_discovers_fields_and_reuses_page_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = AuthProfile(
        type="auto",
        target_hosts=["portal"],
        login_url="http://portal/login",
        verification_url="http://portal/home",
        logged_in_indicator="1@qq.com",
    )
    posted: dict = {}

    class CookieStore(dict):
        jar = [SimpleNamespace(name="pre-session", value="cookie-value")]

    class Client:
        def __init__(self, **_kwargs):
            self.cookies = CookieStore()

        def __enter__(self): return self
        def __exit__(self, *_args): return None

        def get(self, url):
            if url.endswith("/login"):
                return httpx.Response(
                    200,
                    text="""
                    <form action="/session" method="post">
                      <input type="hidden" name="csrf" value="csrf-token">
                      <input type="email" name="account">
                      <input type="password" name="secret">
                      <button type="submit" name="commit" value="Sign in"></button>
                    </form>
                    """,
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(
                200,
                text="Welcome 1@qq.com",
                request=httpx.Request("GET", url),
            )

        def request(self, method, url, **kwargs):
            posted.update({"method": method, "url": url, "data": kwargs["data"]})
            return httpx.Response(
                200,
                text="Welcome 1@qq.com",
                request=httpx.Request(method, url),
            )

    monkeypatch.setattr("app.auth_session.httpx.Client", lambda **kwargs: Client(**kwargs))
    with use_auth_credentials(
        AuthCredentialOverride(
            auth_ref="custom",
            profile=profile,
            username="1@qq.com",
            password="test-password",
        )
    ):
        session = authenticate("custom")

    assert session.authenticated
    assert posted == {
        "method": "POST",
        "url": "http://portal/session",
        "data": {
            "csrf": "csrf-token",
            "account": "1@qq.com",
            "secret": "test-password",
            "commit": "Sign in",
        },
    }


def _response(url: str, text: str, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        text=text,
        headers={"content-type": "text/html"},
        request=httpx.Request("GET", url),
    )


class _ValidationClient:
    def __enter__(self): return self
    def __exit__(self, *_args): return None
    def request(self, method: str, url: str, **_kwargs):
        if "'" in url or "%27" in url:
            return _response(url, "You have an error in your SQL syntax")
        return _response(
            url,
            '<html><a href="/item?id=1">item</a></html>',
        )


class _ReflectionClient:
    def __enter__(self): return self
    def __exit__(self, *_args): return None
    def request(self, method: str, url: str, **kwargs):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        reflected = query.get("name", [""])[0]
        return _response(
            url,
            f"<html>MariaDB reference {reflected}</html>",
        )


def test_active_validation_finds_sql_differential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.adapters.active_validation.httpx.Client",
        lambda **_kwargs: _ValidationClient(),
    )
    adapter = ActiveValidationAdapter()
    findings = adapter.run("http://dvwa/", _scope_options())
    assert any(item.vuln_type == "sql_injection" for item in findings)
    assert SQL_ERROR_PATTERNS.search("You have an error in your SQL syntax")


def test_active_validation_suppresses_reflected_marker_and_static_sql_noise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.adapters.active_validation.httpx.Client",
        lambda **_kwargs: _ReflectionClient(),
    )
    options = {
        **_scope_options(),
        "validation_level": "deep",
        "oast_enabled": False,
    }
    findings = ActiveValidationAdapter().run(
        "http://dvwa/reflect?name=x",
        options,
    )
    assert not any(item.vuln_type == "command_injection" for item in findings)
    assert not any(item.vuln_type == "sql_injection" for item in findings)


def test_active_validation_detects_json_sql_boolean_differential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Client:
        def __enter__(self): return self
        def __exit__(self, *_args): return None

        def request(self, _method, url, **_kwargs):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            value = query.get("q", [""])[0]
            count = 10 if "OR 1=1" in value.upper() else 1
            return httpx.Response(
                200,
                json={"data": [{"id": index} for index in range(count)]},
                headers={"content-type": "application/json"},
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr(
        "app.adapters.active_validation.httpx.Client",
        lambda **_kwargs: Client(),
    )
    findings = ActiveValidationAdapter().run(
        "http://dvwa/search?q=",
        {**_scope_options(), "validation_level": "deep", "oast_enabled": False},
    )
    finding = next(item for item in findings if item.vuln_type == "sql_injection")
    assert finding.evidence["technique"] == "boolean_differential"
    assert finding.evidence["attack_items"] > finding.evidence["baseline_items"]


def test_auth_analysis_detects_weak_session_and_default_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    weak_file = tmp_path / "weak.txt"
    weak_file.write_text("admin:password\n", encoding="utf-8")
    profile = AuthProfile(
        type="form",
        login_url="http://dvwa/login.php",
        session_samples=2,
        weak_credentials_file=str(weak_file),
    )
    sessions = [
        AuthSession(
            authenticated=True,
            cookies={"sid": "a"},
            pre_login_cookies={"sid": "a"},
        ),
        AuthSession(
            authenticated=True,
            cookies={"sid": "a"},
            pre_login_cookies={"sid": "a"},
        ),
    ]
    monkeypatch.setattr(
        "app.adapters.auth_analysis.get_auth_profile",
        lambda _auth_ref: profile,
    )
    monkeypatch.setattr(
        "app.adapters.auth_analysis.authenticate",
        lambda _auth_ref, sample=0: sessions[sample % len(sessions)],
    )
    monkeypatch.setattr(
        "app.adapters.auth_analysis.authenticate_with_credentials",
        lambda *_args, **_kwargs: AuthSession(authenticated=True, cookies={"sid": "a"}),
    )
    options = {
        **_scope_options(),
        "auth_ref": "portal",
        "validation_level": "deep",
    }
    findings = AuthAnalysisAdapter().run("http://dvwa/", options)
    types = {item.vuln_type for item in findings}
    assert "weak_session_id" in types
    assert "session_fixation" in types
    assert "default_credentials" in types


def test_oast_service_flow(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import importlib.util
    import sqlite3
    from fastapi.testclient import TestClient

    monkeypatch.setenv("OAST_DATABASE", str(tmp_path / "oast.db"))
    monkeypatch.setenv("OAST_SECRET", "test-secret")
    path = Path(__file__).parents[1] / "oast" / "app.py"
    spec = importlib.util.spec_from_file_location("test_oast_app", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    client = TestClient(module.app)
    created = client.post(
        "/api/tokens",
        headers={"X-OAST-Secret": "test-secret"},
        json={"label": "test"},
    )
    assert created.status_code == 200
    token = created.json()["token"]
    callback = client.get(f"/cb/{token}?probe=1")
    assert callback.status_code == 204
    hits = client.get(
        f"/api/tokens/{token}",
        headers={"X-OAST-Secret": "test-secret"},
    )
    assert hits.status_code == 200
    assert len(hits.json()["hits"]) == 1
