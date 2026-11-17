from __future__ import annotations

from pathlib import Path

import pytest

from app.config import settings
from app.guard import GuardError, validate_scope, validate_task
from app.schemas.task import TaskCreate


def _task(**overrides) -> TaskCreate:
    payload = {
        "target": "http://dvwa",
        "auth_ref": "local-dvwa",
        "authorization_confirmed": True,
        "max_rps": 5,
        "mode": "active",
    }
    payload.update(overrides)
    return TaskCreate(**payload)


def test_valid_local_dvwa_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    auth_file = tmp_path / "auth.yaml"
    auth_file.write_text(
        "auth_refs:\n  local-dvwa:\n    scope: [dvwa, 127.0.0.1, localhost]\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "authorization_file", str(auth_file))
    monkeypatch.setattr("app.guard._resolve_addresses", lambda _host: ["172.19.0.5"])

    decision = validate_task(_task())

    assert decision.host == "dvwa"
    assert decision.max_rps == 5


def test_arbitrary_public_target_is_allowed_after_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.guard._resolve_addresses", lambda _host: ["8.8.8.8"])

    decision = validate_task(
        _task(target="https://www.school.edu.cn/", auth_ref="none")
    )

    assert decision.auth_ref == "none"
    assert decision.host == "www.school.edu.cn"
    assert decision.scope == ["www.school.edu.cn"]


def test_explicit_local_service_name_can_resolve_to_private_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.guard._resolve_addresses", lambda _host: ["172.19.0.12"])

    decision = validate_scope(
        "http://juice-shop:3000",
        ["juice-shop"],
        [],
    )

    assert decision.host == "juice-shop"
    assert decision.resolved_ips == ["172.19.0.12"]


def test_public_hostname_resolving_private_is_still_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.guard._resolve_addresses", lambda _host: ["172.19.0.12"])

    with pytest.raises(GuardError, match="DNS rebinding"):
        validate_scope(
            "http://rebind.example.com",
            ["rebind.example.com"],
            [],
        )


def test_authorization_confirmation_is_required() -> None:
    with pytest.raises(GuardError, match="authorization confirmation"):
        validate_task(
            _task(
                target="https://www.school.edu.cn/",
                auth_ref="none",
                authorization_confirmed=False,
            )
        )


@pytest.mark.parametrize(
    "payload",
    [
        {"target": "http://dvwa", "auth_ref": "local-dvwa", "max_rps": 6},
        {"target": "http://dvwa", "auth_ref": "missing"},
    ],
)
def test_guard_rejects_invalid_tasks(
    payload: dict,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_file = tmp_path / "auth.yaml"
    auth_file.write_text(
        "auth_refs:\n  local-dvwa:\n    scope: [dvwa, localhost]\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "authorization_file", str(auth_file))

    with pytest.raises(GuardError):
        validate_task(_task(**payload))


def test_wildcard_scope_and_dns_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.guard._resolve_addresses", lambda _host: ["10.0.0.8"])
    decision = validate_scope(
        "http://api.corp.local",
        ["*.corp.local"],
        ["10.0.0.0/8"],
    )
    assert decision.host == "api.corp.local"

    monkeypatch.setattr("app.guard._resolve_addresses", lambda _host: ["203.0.113.5"])
    with pytest.raises(GuardError, match="DNS rebinding"):
        validate_scope(
            "http://api.corp.local",
            ["*.corp.local"],
            ["10.0.0.0/8"],
        )
