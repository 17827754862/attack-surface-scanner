from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from app.adapters.httpx_adapter import HttpxAdapter
from app.adapters.nmap_adapter import NmapAdapter
from app.guard import GuardError, ScopeDecision, validate_scope
from app.graph.nodes import (
    _discover_client_assets,
    _discover_common_endpoints,
    _is_local_or_single_label,
)
from app.schemas.finding import Finding
from app.schemas.task import TaskCreate
from app.guard import validate_task


def _scope(candidate, scope, cidrs):
    host = candidate.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if host not in {"dvwa", "127.0.0.1"}:
        raise GuardError("outside scope")
    return ScopeDecision(candidate, host, ["dvwa"], ["172.19.0.2"])


def test_redirect_to_external_is_blocked_before_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.adapters.base.validate_scope", _scope)
    requested: list[str] = []

    class Client:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def get(self, url):
            requested.append(url)
            return SimpleNamespace(
                is_redirect=True,
                headers={"location": "http://outside.invalid/"},
                url="http://dvwa/",
            )

    monkeypatch.setattr("app.adapters.httpx_adapter.http_client.Client", lambda **_kwargs: Client())
    adapter = HttpxAdapter({"httpx": {"available": True}})
    options = {
        "max_rps": 5,
        "scope": ["dvwa"],
        "allowed_cidrs": ["172.16.0.0/12"],
        "blocked_targets": [],
    }
    findings = adapter._http_fallback(["http://dvwa"], 5, options)
    assert findings == []
    assert requested == ["http://dvwa"]
    assert any("outside.invalid" in item for item in options["blocked_targets"])


def test_openapi_server_outside_scope_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.graph.nodes.validate_scope", _scope)

    class Response:
        status_code = 200
        headers = {"content-type": "application/json"}
        text = '{"openapi":"3.0.0","servers":[{"url":"http://outside.invalid"}]}'
        is_redirect = False
        url = "http://dvwa/swagger.json"
        def json(self):
            return {"openapi": "3.0.0", "servers": [{"url": "http://outside.invalid"}]}

    class Client:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def get(self, _url): return Response()

    monkeypatch.setattr("app.graph.nodes.httpx.Client", lambda **_kwargs: Client())
    options = {
        "scope": ["dvwa"],
        "allowed_cidrs": ["172.16.0.0/12"],
        "blocked_targets": [],
    }
    result = _discover_common_endpoints(
        {"max_rps": 5},
        [{"url": "http://dvwa/", "host": "dvwa"}],
        options,
    )
    assert any(item["url"] == "http://dvwa/swagger.json" for item in result)
    assert all(item["url"] != "http://outside.invalid" for item in result)
    assert any("outside.invalid" in item for item in options["blocked_targets"])


def test_resolved_ip_findings_remain_authorized() -> None:
    adapter = NmapAdapter()
    options = {
        "scope": ["juice-shop"],
        "allowed_cidrs": [],
        "resolved_ips": ["172.19.0.12"],
        "blocked_targets": [],
    }
    finding = Finding(
        source="nmap",
        host="172.19.0.12",
        port=3000,
        vuln_type="open_port",
        severity="info",
        evidence={"service": "http"},
    )

    assert adapter._filter_findings([finding], options) == [finding]


def test_reserved_test_hostname_can_resolve_to_private_lab_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.guard._resolve_addresses",
        lambda _host: ["172.19.0.13"],
    )
    decision = validate_scope("http://dvwa.test", ["dvwa.test"], [])
    assert decision.host == "dvwa.test"
    assert decision.resolved_ips == ["172.19.0.13"]


def test_reserved_test_domain_skips_public_subdomain_enumeration() -> None:
    assert _is_local_or_single_label("dvwa.test")
    assert _is_local_or_single_label("webgoat.test")
    assert not _is_local_or_single_label("example.com")


def test_custom_auth_reference_is_preserved_for_worker_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.guard._resolve_addresses",
        lambda _host: ["172.19.0.13"],
    )
    decision = validate_task(
        TaskCreate(
            target="http://webgoat.test",
            auth_ref="custom",
            authorization_confirmed=True,
        )
    )
    assert decision.auth_ref == "custom"


def test_regular_domain_cannot_resolve_to_private_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.guard._resolve_addresses",
        lambda _host: ["192.168.1.20"],
    )
    with pytest.raises(GuardError, match="DNS rebinding blocked"):
        validate_scope("http://internal.example.com", ["internal.example.com"], [])


def test_spa_asset_discovery_extracts_scripts_and_api_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.graph.nodes.validate_scope",
        lambda candidate, _scope, _cidrs: ScopeDecision(
            candidate,
            "juice-shop",
            ["juice-shop"],
            ["172.19.0.12"],
        ),
    )
    main_js = """
    const products = this.http.get(`${this.hostServer}/rest/products/search?q=${t}`);
    const users = this.http.get(this.hostServer + `/api/Users`);
    """

    class Client:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def get(self, url):
            if url == "http://juice-shop:3000":
                return httpx.Response(
                    200,
                    text='<script src="main.js"></script><a href="/ftp">files</a>',
                    request=httpx.Request("GET", url),
                )
            return httpx.Response(
                200,
                text=main_js,
                request=httpx.Request("GET", url),
            )

    monkeypatch.setattr("app.graph.nodes.httpx.Client", lambda **_kwargs: Client())
    discovered = _discover_client_assets(
        {"target": "http://juice-shop:3000", "max_rps": 5},
        [{"url": "http://juice-shop:3000"}],
        {
            "scope": ["juice-shop"],
            "allowed_cidrs": [],
            "auth_scan": False,
        },
    )
    urls = {item["url"] for item in discovered}
    assert "http://juice-shop:3000/main.js" in urls
    assert "http://juice-shop:3000/rest/products/search?q=" in urls
    assert "http://juice-shop:3000/api/Users" in urls
