from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import settings
from .schemas.task import TaskCreate


class GuardError(ValueError):
    """Raised when authorization, scope, or DNS validation fails."""


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    host: str
    scope: list[str]
    resolved_ips: list[str]


@dataclass(frozen=True)
class GuardDecision:
    target: str
    host: str
    scope: list[str]
    auth_ref: str
    max_rps: int
    mode: str
    tool_profile: str
    validation_level: str
    oast_enabled: bool
    allowed_cidrs: list[str]
    resolved_ips: list[str]


NO_AUTH_REFS = {"", "none", "unauthenticated"}


def normalize_target(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        raise GuardError("target is required")
    parsed = urllib.parse.urlparse(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or raw.split("/", 1)[0].split(":", 1)[0]).strip().lower()
    if not host:
        raise GuardError("target host cannot be parsed")
    if "*" in host:
        raise GuardError("wildcard targets are not allowed")
    if "/" in raw and "://" not in raw and not _is_network(raw):
        raise GuardError("CIDR and path-only targets are not allowed")
    return host


def _is_network(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _scope_matches(host: str, scope: str) -> bool:
    value = scope.strip().lower().lstrip(".")
    if value.startswith("*."):
        suffix = value[2:]
        return host != suffix and host.endswith("." + suffix)
    try:
        address = ipaddress.ip_address(host)
        network = ipaddress.ip_network(value, strict=False)
        return address in network
    except ValueError:
        return host == value or host.endswith("." + value)


def _resolve_addresses(host: str) -> list[str]:
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise GuardError(f"DNS resolution failed for {host}: {exc}") from exc
    return sorted({str(row[4][0]) for row in rows})


def _is_private_scope(scope: list[str]) -> bool:
    for item in scope:
        value = item.strip().lower().strip(".")
        if value and "." not in value and not value.startswith("*"):
            return True
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.is_private or network.is_loopback or network.is_link_local:
                return True
        except ValueError:
            continue
    return False


def _is_local_lab_host(host: str) -> bool:
    value = host.strip().lower().rstrip(".")
    return (
        value.endswith(".test")
        or value.endswith(".localhost")
        or value == "host.docker.internal"
        or "." not in value
    )


def validate_scope(
    url_or_host: str,
    scope: list[str] | str,
    allowed_cidrs: list[str] | str | None = None,
) -> ScopeDecision:
    host = normalize_target(url_or_host)
    values = [scope] if isinstance(scope, str) else list(scope)
    values = [str(item).strip().lower() for item in values if str(item).strip()]
    if not values:
        raise GuardError("authorization scope is empty")
    if not any(_scope_matches(host, item) for item in values):
        raise GuardError(f"target {host!r} is outside the authorized scope")

    resolved = _resolve_addresses(host)
    cidrs = [allowed_cidrs] if isinstance(allowed_cidrs, str) else list(allowed_cidrs or [])
    cidrs = [str(item).strip() for item in cidrs if str(item).strip()]
    if cidrs:
        networks = [ipaddress.ip_network(item, strict=False) for item in cidrs]
        for value in resolved:
            address = ipaddress.ip_address(value)
            if not any(address in network for network in networks):
                raise GuardError(
                    f"DNS rebinding blocked for {host}: {value} is outside allowed CIDRs"
                )

    explicit_ips: set[str] = set()
    for item in values:
        try:
            explicit_ips.add(str(ipaddress.ip_address(item)))
        except ValueError:
            continue
    metadata = ipaddress.ip_network("169.254.169.254/32")
    for value in resolved:
        address = ipaddress.ip_address(value)
        if address in metadata and value not in explicit_ips:
            raise GuardError(f"metadata address blocked for {host}: {value}")
        if (
            not cidrs
            and address.is_private
            and not _is_private_scope(values)
            and not _is_local_lab_host(host)
            and value not in explicit_ips
        ):
            raise GuardError(f"DNS rebinding blocked for {host}: private address {value}")

    return ScopeDecision(
        target=url_or_host,
        host=host,
        scope=values,
        resolved_ips=resolved,
    )


def load_authorizations(path: str | None = None) -> dict[str, Any]:
    auth_path = Path(path or settings.authorization_file)
    if not auth_path.exists():
        return {}
    payload = yaml.safe_load(auth_path.read_text(encoding="utf-8")) or {}
    return payload


def authorization_entry(auth_ref: str) -> dict[str, Any]:
    payload = load_authorizations()
    refs = payload.get("auth_refs") or {}
    entry = refs.get(auth_ref) if isinstance(refs, dict) else None
    if entry is None and payload.get("auth_ref") == auth_ref:
        entry = payload
    if not isinstance(entry, dict):
        raise GuardError(f"unknown auth_ref: {auth_ref}")
    return entry


def scope_for_auth_ref(auth_ref: str) -> tuple[list[str], list[str]]:
    entry = authorization_entry(auth_ref)
    raw_scope = entry.get("scope") or settings.default_scope.split(",")
    if isinstance(raw_scope, str):
        raw_scope = [item.strip() for item in raw_scope.split(",") if item.strip()]
    scope = [str(item).strip().lower() for item in raw_scope if str(item).strip()]
    raw_cidrs = entry.get("allowed_cidrs") or []
    if isinstance(raw_cidrs, str):
        raw_cidrs = [item.strip() for item in raw_cidrs.split(",") if item.strip()]
    return scope, [str(item).strip() for item in raw_cidrs if str(item).strip()]


def validate_task(task: TaskCreate) -> GuardDecision:
    if not task.authorization_confirmed:
        raise GuardError(
            "authorization confirmation is required; only scan targets you own "
            "or have explicit permission to test"
        )
    auth_ref = (task.auth_ref or "none").strip().lower()
    if task.max_rps < 1 or task.max_rps > 5:
        raise GuardError("max_rps must be between 1 and 5")
    if auth_ref == "custom":
        scope = [normalize_target(task.target)]
        allowed_cidrs: list[str] = []
    elif auth_ref in NO_AUTH_REFS:
        auth_ref = "none"
        scope = [normalize_target(task.target)]
        allowed_cidrs: list[str] = []
    else:
        scope, allowed_cidrs = scope_for_auth_ref(auth_ref)
    decision = validate_scope(task.target, scope, allowed_cidrs)
    return GuardDecision(
        target=task.target,
        host=decision.host,
        scope=decision.scope,
        auth_ref=auth_ref,
        max_rps=task.max_rps,
        mode=task.mode,
        tool_profile=task.tool_profile,
        validation_level=task.validation_level,
        oast_enabled=task.oast_enabled,
        allowed_cidrs=allowed_cidrs,
        resolved_ips=decision.resolved_ips,
    )
