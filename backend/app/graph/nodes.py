from __future__ import annotations

import ipaddress
import os
import re
import time
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

import fcntl
import httpx

from ..adapters import (
    ActiveValidationAdapter,
    AuthAnalysisAdapter,
    DnsxAdapter,
    GitleaksAdapter,
    HttpxAdapter,
    KubescapeAdapter,
    NiktoAdapter,
    NmapAdapter,
    NucleiAdapter,
    OpenvasAdapter,
    SchemathesisAdapter,
    SubfinderAdapter,
    SubjackAdapter,
    WapitiAdapter,
    ZapAdapter,
)
from ..adapters.base import AdapterCancelled
from ..ai_config import load_ai_config
from ..ai_service import analyze_risk_groups, choose_next_scan_node
from ..auth_session import authenticate, get_auth_profile
from ..config import settings
from ..db import SessionLocal
from ..dedup import merge_findings
from ..evidence import EvidenceStore
from ..guard import (
    GuardError,
    normalize_target,
    scope_for_auth_ref,
    validate_scope,
    validate_task,
)
from ..lab_benchmark import evaluate_lab_benchmark
from ..playbooks import playbook_for
from ..redaction import redact, redact_text
from ..report import render_report
from ..risk_groups import build_risk_groups
from ..memory import complete_memory_context
from ..schemas.finding import Finding
from ..schemas.task import TaskCreate
from .state import PentestState


NODE_NAMES = [
    "auth_gate",
    "recon",
    "dns_resolve",
    "takeover_check",
    "http_probe",
    "port_scan",
    "credential_session_analysis",
    "router",
    "web_scan",
    "nuclei_scan",
    "js_secret_scan",
    "api_fuzz",
    "k8s_audit",
    "server_baseline",
    "active_validation",
    "host_vuln_scan",
    "merge_and_score",
    "llm_summarize",
    "report",
]

SCAN_NODES = [
    "web_scan",
    "nuclei_scan",
    "js_secret_scan",
    "api_fuzz",
    "k8s_audit",
    "server_baseline",
    "active_validation",
    "host_vuln_scan",
]

TOOL_PROFILE_ROUTES = {
    "full_agent": set(SCAN_NODES),
    "nuclei": {"nuclei_scan"},
    "zap_wapiti_nuclei": {"web_scan", "nuclei_scan", "server_baseline"},
    "validation_only": {"active_validation"},
}


@contextmanager
def _exclusive_file_lock(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


NODE_TOOL = {
    "auth_gate": "guard",
    "recon": "subfinder",
    "dns_resolve": "dnsx",
    "takeover_check": "subjack",
    "http_probe": "httpx",
    "port_scan": "nmap",
    "credential_session_analysis": "auth-analysis",
    "router": "decision",
    "web_scan": "zap",
    "nuclei_scan": "nuclei",
    "js_secret_scan": "gitleaks",
    "api_fuzz": "schemathesis",
    "k8s_audit": "kubescape",
    "server_baseline": "nikto+wapiti",
    "active_validation": "safe-validators",
    "host_vuln_scan": "openvas",
    "merge_and_score": "dedup",
    "llm_summarize": "optional-llm",
    "report": "jinja2+mermaidx",
}

_cancel_checker = lambda: False


def set_cancel_checker(checker) -> None:
    global _cancel_checker
    _cancel_checker = checker or (lambda: False)


def cancel_requested() -> bool:
    return bool(_cancel_checker())


def initial_node_status() -> dict[str, str]:
    return {name: "pending" for name in NODE_NAMES}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _update(
    state: PentestState,
    node: str,
    status: str,
    summary: str,
    error: str | None = None,
    record_error: bool = True,
) -> dict[str, Any]:
    trace = {
        "node_name": node,
        "tool_name": NODE_TOOL.get(node, ""),
        "started_at": _now(),
        "finished_at": _now(),
        "status": status,
        "output_summary": summary,
        "error": error,
    }
    # Return only this node's delta. LangGraph merges it with the dict reducer.
    node_status = {node: status}
    update: dict[str, Any] = {
        "current_node": node,
        "node_status": node_status,
        "execution_trace": [trace],
    }
    if error and record_error:
        update["errors"] = [error]
    return update


def _adapter(adapter_cls, state: PentestState, node: str):
    return adapter_cls(
        state.get("capabilities") or {},
        cancel_check=cancel_requested,
    )


def _as_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [finding.model_dump() for finding in findings]


def _unique_origins(urls: list[str]) -> list[str]:
    origins: set[str] = set()
    for value in urls:
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme and parsed.netloc:
            origins.add(f"{parsed.scheme}://{parsed.netloc}")
    return sorted(origins)


def _validation_seeds(state: PentestState) -> list[str]:
    urls = [
        str(item.get("url"))
        for item in state.get("live_endpoints", [])
        if item.get("url")
    ]
    ordered = _unique_origins(urls)
    api_urls = [
        value
        for value in urls
        if "?" in value
        or "/rest/" in value.lower()
        or "/api/" in value.lower()
    ]
    return list(dict.fromkeys([*ordered, *api_urls]))


def _skipped(state: PentestState, node: str, tool: str) -> dict[str, Any]:
    return _update(state, node, "skipped", "", f"tool_not_installed: {tool}")


def _skipped_reason(
    state: PentestState,
    node: str,
    reason: str,
) -> dict[str, Any]:
    return _update(state, node, "skipped", "", reason, record_error=False)


def _is_local_or_single_label(host: str) -> bool:
    value = host.strip().lower()
    if value in {"localhost", "host.docker.internal"}:
        return True
    if value.endswith(".test") or value.endswith(".localhost"):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return "." not in value


def _scope_options(state: PentestState) -> dict[str, Any]:
    scope = state.get("scope") or []
    allowed_cidrs = state.get("allowed_cidrs") or []
    if not scope:
        if state.get("auth_ref") == "custom":
            scope, allowed_cidrs = [normalize_target(state["target"])], []
        else:
            scope, allowed_cidrs = scope_for_auth_ref(state.get("auth_ref", ""))
    try:
        profile = get_auth_profile(state.get("auth_ref", ""))
        auth_scan = profile.type != "none" and profile.applies_to(state["target"])
        safe_path_denylist = profile.safe_path_denylist
        active_scan_exclude = profile.active_scan_exclude
    except Exception:
        auth_scan = False
        safe_path_denylist = []
        active_scan_exclude = []
    defaults = [
        item.strip()
        for item in str(getattr(settings, "safe_scan_denylist", "")).split(",")
        if item.strip()
    ]
    safe_path_denylist = list(dict.fromkeys([*defaults, *(safe_path_denylist or [])]))
    return {
        "max_rps": state.get("max_rps", 5),
        "mode": state.get("mode", "active"),
        "tool_profile": state.get("tool_profile", "full_agent"),
        "scope": scope,
        "allowed_cidrs": allowed_cidrs,
        "resolved_ips": state.get("resolved_ips") or [],
        "blocked_targets": [],
        "auth_ref": state.get("auth_ref", ""),
        "auth_scan": auth_scan,
        "validation_level": state.get("validation_level", "safe"),
        "oast_enabled": bool(state.get("oast_enabled")),
        "safe_path_denylist": safe_path_denylist,
        "active_scan_exclude": active_scan_exclude,
        "validation_max_pages": settings.validation_max_pages,
        "validation_max_parameters": settings.validation_max_parameters,
        "validation_max_requests": settings.validation_max_requests,
        "lab_benchmark_enabled": settings.lab_benchmark_enabled,
    }


def _blocked_update(options: dict[str, Any]) -> dict[str, Any]:
    blocked = list(dict.fromkeys(options.get("blocked_targets") or []))
    return {"blocked_targets": blocked} if blocked else {}


def _exception_update(
    state: PentestState,
    node: str,
    tool: str,
    exc: Exception,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if isinstance(exc, AdapterCancelled):
        return {
            **_update(state, node, "failed", "cancelled", "task_cancelled"),
            "status": "cancelled",
            "cancelled": True,
            "resume_from": node,
        }
    return {
        **_update(state, node, "failed", f"{tool} failed", redact_text(str(exc))),
        **(_blocked_update(options) if options else {}),
    }


def node_auth_gate(state: PentestState) -> dict[str, Any]:
    if cancel_requested():
        return {
            **_update(state, "auth_gate", "skipped", "cancelled", "task_cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    task = TaskCreate(
        target=state["target"],
        auth_ref=state.get("auth_ref") or "none",
        max_rps=state.get("max_rps", 5),
        mode=state.get("mode", "active"),
        tool_profile=state.get("tool_profile", "full_agent"),
        validation_level=state.get("validation_level", "safe"),
        oast_enabled=bool(state.get("oast_enabled")),
        authorization_confirmed=True,
    )
    try:
        decision = validate_task(task)
        return {
            **_update(state, "auth_gate", "done", f"scope={len(decision.scope)}"),
            "scope": decision.scope,
            "allowed_cidrs": decision.allowed_cidrs,
            "resolved_ips": decision.resolved_ips,
            "status": "running",
        }
    except GuardError as exc:
        return {
            **_update(state, "auth_gate", "failed", "blocked", str(exc)),
            "status": "blocked",
            "errors": [str(exc)],
        }


def node_recon(state: PentestState) -> dict[str, Any]:
    if cancel_requested():
        return {
            **_update(state, "recon", "skipped", "cancelled", "task_cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    host = urllib.parse.urlparse(
        state["target"] if "://" in state["target"] else f"//{state['target']}"
    ).hostname or state["target"]
    if _is_local_or_single_label(host):
        return {
            **_update(
                state,
                "recon",
                "done",
                f"local target; public subdomain enumeration skipped: {host}",
            ),
            "subdomains": [host],
        }
    adapter = _adapter(SubfinderAdapter, state, "recon")
    if not adapter.available():
        return {**_skipped(state, "recon", "subfinder"), "subdomains": [host]}
    try:
        options = _scope_options(state)
        findings = adapter.run(host, options)
        subdomains = sorted(
            {
                str(item.evidence.get("subdomain") or item.host)
                for item in findings
                if item.evidence.get("subdomain") or item.host
            }
            | {host}
        )
        return {
            **_update(state, "recon", "done", f"subdomains: {len(subdomains)}"),
            "subdomains": subdomains,
            **_blocked_update(options),
        }
    except Exception as exc:
        return {
            **_exception_update(state, "recon", "subfinder", exc),
            "subdomains": [host],
        }


def node_dns_resolve(state: PentestState) -> dict[str, Any]:
    if cancel_requested():
        return {
            **_update(state, "dns_resolve", "skipped", "cancelled", "task_cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    adapter = _adapter(DnsxAdapter, state, "dns_resolve")
    subdomains = state.get("subdomains") or [state["target"]]
    if all(_is_local_or_single_label(item) for item in subdomains):
        return {
            **_update(state, "dns_resolve", "done", f"local hosts: {len(subdomains)}"),
            "resolved_hosts": subdomains,
        }
    if not adapter.available():
        return {**_skipped(state, "dns_resolve", "dnsx"), "resolved_hosts": subdomains}
    try:
        options = _scope_options(state)
        findings = adapter.run(subdomains, options)
        resolved = sorted({item.host for item in findings if item.host} | set(subdomains))
        return {
            **_update(state, "dns_resolve", "done", f"resolved hosts: {len(resolved)}"),
            "resolved_hosts": resolved,
            **_blocked_update(options),
        }
    except Exception as exc:
        return {
            **_exception_update(state, "dns_resolve", "dnsx", exc, locals().get("options")),
            "resolved_hosts": subdomains,
        }


def node_takeover_check(state: PentestState) -> dict[str, Any]:
    if cancel_requested():
        return {
            **_update(state, "takeover_check", "skipped", "cancelled", "task_cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    adapter = _adapter(SubjackAdapter, state, "takeover_check")
    if all(
        _is_local_or_single_label(item)
        for item in state.get("subdomains", [])
    ):
        return _skipped_reason(
            state,
            "takeover_check",
            "local_targets_do_not_support_takeover_checks",
        )
    if not adapter.available():
        return _skipped(state, "takeover_check", "subjack")
    try:
        options = _scope_options(state)
        findings = adapter.run(state.get("subdomains", []), options)
        return {
            **_update(state, "takeover_check", "done", f"{len(findings)} takeover"),
            "takeover_findings": _as_dicts(findings),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "takeover_check", "subjack", exc, locals().get("options"))


def node_http_probe(state: PentestState) -> dict[str, Any]:
    if cancel_requested():
        return {
            **_update(state, "http_probe", "skipped", "cancelled", "task_cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    adapter = _adapter(HttpxAdapter, state, "http_probe")
    if not adapter.available():
        return _skipped(state, "http_probe", "httpx")
    hosts = state.get("resolved_hosts") or [state["target"]]
    urls = [state["target"] if "://" in state["target"] else f"http://{state['target']}"]
    urls.extend(f"http://{host}" for host in hosts if host not in urls)
    try:
        options = _scope_options(state)
        findings = adapter.run(urls, options)
        endpoints = [
            {
                "url": item.url,
                "host": item.host,
                "port": item.port,
                **item.evidence,
            }
            for item in findings
        ]
        endpoints.extend(_discover_common_endpoints(state, endpoints, options))
        endpoints.extend(_discover_client_assets(state, endpoints, options))
        unique_endpoints: dict[str, dict[str, Any]] = {}
        for endpoint in endpoints:
            url = str(endpoint.get("url") or "")
            if url:
                unique_endpoints[url] = endpoint
        endpoints = list(unique_endpoints.values())
        return {
            **_update(state, "http_probe", "done", f"live endpoints: {len(endpoints)}"),
            "live_endpoints": endpoints,
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "http_probe", "httpx", exc, locals().get("options"))


def node_port_scan(state: PentestState) -> dict[str, Any]:
    if cancel_requested():
        return {
            **_update(state, "port_scan", "skipped", "cancelled", "task_cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    if state.get("tool_profile") != "full_agent":
        return _skipped_reason(
            state,
            "port_scan",
            f"tool_profile_excluded: {state.get('tool_profile')}",
        )
    adapter = _adapter(NmapAdapter, state, "port_scan")
    if not adapter.available():
        return _skipped(state, "port_scan", "nmap")
    try:
        options = _scope_options(state)
        findings = adapter.run(
            state.get("resolved_hosts", []),
            options,
        )
        return {
            **_update(state, "port_scan", "done", f"open ports: {len(findings)}"),
            "port_findings": _as_dicts(findings),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "port_scan", "nmap", exc, locals().get("options"))


def node_credential_session_analysis(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(
                state,
                "credential_session_analysis",
                "skipped",
                "cancelled",
            ),
            "status": "cancelled",
            "cancelled": True,
        }
    if state.get("validation_level", "safe") == "off":
        return _skipped_reason(
            state,
            "credential_session_analysis",
            "validation_disabled",
        )
    try:
        profile = get_auth_profile(state.get("auth_ref", ""))
    except Exception as exc:
        return _skipped_reason(
            state,
            "credential_session_analysis",
            f"auth_profile_unavailable: {redact_text(str(exc))}",
        )
    if profile.type not in {"auto", "form", "json"}:
        return _skipped_reason(
            state,
            "credential_session_analysis",
            "login_authentication_not_configured",
        )
    adapter = _adapter(
        AuthAnalysisAdapter,
        state,
        "credential_session_analysis",
    )
    try:
        options = _scope_options(state)
        findings = adapter.run(state["target"], options)
        return {
            **_update(
                state,
                "credential_session_analysis",
                "done",
                f"{len(findings)} authentication findings",
            ),
            "vuln_findings": _as_dicts(findings),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(
            state,
            "credential_session_analysis",
            "auth-analysis",
            exc,
            locals().get("options"),
        )


def _router_exclusion_reason(
    state: PentestState,
    node: str,
    allowed: set[str],
    profile: str,
) -> str:
    if state.get("mode") == "passive":
        return "passive_mode_no_active_scan"
    if node not in allowed:
        return f"tool_profile_excluded: {profile}"
    if node == "host_vuln_scan" and state.get("mode") != "full":
        return "full_mode_disabled"
    return "condition_not_met"


def _routing_context(
    state: PentestState,
    remaining: list[str],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for key in (
        "takeover_findings",
        "port_findings",
        "vuln_findings",
        "api_findings",
        "k8s_findings",
        "secret_findings",
    ):
        findings.extend(state.get(key) or [])
    compact_findings = []
    seen: set[tuple[str, str, str]] = set()
    for item in findings:
        marker = (
            str(item.get("source") or ""),
            str(item.get("vuln_type") or ""),
            str(item.get("url") or item.get("host") or ""),
        )
        if marker in seen:
            continue
        seen.add(marker)
        compact_findings.append(
            {
                "source": marker[0],
                "type": marker[1],
                "severity": item.get("severity"),
                "target": marker[2],
            }
        )
        if len(compact_findings) >= 30:
            break
    trace = list(state.get("execution_trace") or [])
    previous_scan = next(
        (
            {
                "node": item.get("node_name"),
                "status": item.get("status"),
                "summary": item.get("output_summary"),
                "error": item.get("error"),
            }
            for item in reversed(trace)
            if item.get("node_name") in SCAN_NODES
        ),
        None,
    )
    return {
        "target": state.get("target"),
        "mode": state.get("mode"),
        "tool_profile": state.get("tool_profile"),
        "validation_level": state.get("validation_level"),
        "live_endpoints": len(state.get("live_endpoints") or []),
        "open_ports": [
            item.get("port")
            for item in (state.get("port_findings") or [])[:20]
            if item.get("port") is not None
        ],
        "has_openapi": any(
            any(token in str(item.get("url", "")).lower() for token in ("swagger", "openapi"))
            for item in (state.get("live_endpoints") or [])
        ),
        "has_javascript": any(
            str(item.get("url", "")).lower().split("?", 1)[0].endswith(".js")
            for item in (state.get("live_endpoints") or [])
        ),
        "previous_scan": previous_scan,
        "completed_scan_nodes": list(state.get("completed_scan_nodes") or []),
        "remaining_candidates": remaining,
        "findings": compact_findings,
        "errors": list(state.get("errors") or [])[-10:],
    }


def node_router(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "router", "skipped", "cancelled"),
            "routes": [],
            "next_scan_node": "merge_and_score",
            "status": "cancelled",
            "cancelled": True,
        }

    ports = {item.get("port") for item in state.get("port_findings", [])}
    endpoints = state.get("live_endpoints", [])
    candidate_routes: list[str] = []
    if endpoints:
        candidate_routes.extend(["web_scan", "nuclei_scan", "server_baseline"])
        if state.get("validation_level", "safe") != "off":
            candidate_routes.append("active_validation")
    if any(
        "swagger" in str(item.get("url", "")).lower()
        or "openapi" in str(item.get("url", "")).lower()
        for item in endpoints
    ):
        candidate_routes.append("api_fuzz")
    if any(
        str(item.get("url", "")).lower().split("?", 1)[0].endswith(".js")
        for item in endpoints
    ):
        candidate_routes.append("js_secret_scan")
    if 6443 in ports:
        candidate_routes.append("k8s_audit")
    if state.get("mode") == "full":
        candidate_routes.append("host_vuln_scan")

    profile = str(state.get("tool_profile") or "full_agent")
    allowed = TOOL_PROFILE_ROUTES.get(profile, TOOL_PROFILE_ROUTES["full_agent"])
    if state.get("mode") == "passive":
        allowed = set()
    routes = [
        route
        for route in dict.fromkeys(candidate_routes)
        if route in allowed
    ]
    current_status = dict(state.get("node_status") or {})
    attempted = {
        node
        for node in SCAN_NODES
        if current_status.get(node) in {"done", "failed", "skipped", "cancelled"}
    }
    completed = [
        node
        for node in SCAN_NODES
        if current_status.get(node) in {"done", "completed"}
    ]
    remaining = [node for node in routes if node not in attempted]

    node_status: dict[str, str] = {"router": "done"}
    execution_trace: list[dict[str, Any]] = []
    for node in SCAN_NODES:
        if node in routes or node in attempted:
            continue
        reason = _router_exclusion_reason(state, node, allowed, profile)
        node_status[node] = "skipped"
        execution_trace.append(
            {
                "node_name": node,
                "tool_name": NODE_TOOL.get(node, ""),
                "started_at": _now(),
                "finished_at": _now(),
                "status": "skipped",
                "output_summary": "",
                "error": reason,
            }
        )

    routing_mode = str(state.get("routing_mode") or "auto")
    routing_error = str(state.get("routing_error") or "")
    routing_source = "fixed"
    routing_reason = ""
    routing_confidence = 0
    chosen = ""
    decision: dict[str, Any] | None = None

    if remaining and routing_mode != "fixed":
        db = None
        try:
            db = SessionLocal()
            config = load_ai_config(db)
            if config.enabled and config.base_url and config.model:
                decision = choose_next_scan_node(
                    candidates=remaining,
                    context=_routing_context(state, remaining),
                    config=config,
                )
                routing_source = "ai"
                chosen = str(decision["next_node"])
                routing_reason = str(decision.get("reason") or "")
                routing_confidence = int(decision.get("confidence") or 0)
                routing_mode = "ai"
            else:
                routing_mode = "fixed"
                routing_error = "ai_not_configured"
        except Exception as exc:
            routing_mode = "fixed"
            routing_error = redact_text(str(exc))
        finally:
            if db is not None:
                db.close()

    if remaining and not chosen:
        chosen = remaining[0]
        routing_source = "fixed"
        routing_reason = "AI 未启用或不可用，按固定安全顺序继续。"
        if not routing_error:
            routing_error = "ai_not_configured"

    if chosen == "finish":
        for node in remaining:
            node_status[node] = "skipped"
            execution_trace.append(
                {
                    "node_name": node,
                    "tool_name": NODE_TOOL.get(node, ""),
                    "started_at": _now(),
                    "finished_at": _now(),
                    "status": "skipped",
                    "output_summary": "",
                    "error": "ai_router_finished",
                }
            )
        next_node = "merge_and_score"
        summary = f"AI 完成编排：{routing_reason or '现有证据已足够'}"
    elif chosen:
        next_node = chosen
        summary = (
            f"{'AI' if routing_source == 'ai' else '固定'} -> {chosen}"
            + (f"：{routing_reason}" if routing_reason else "")
        )
    else:
        next_node = "merge_and_score"
        summary = "没有需要继续执行的扫描节点"

    decision_record = {
        "step": len(state.get("scan_decisions") or []) + 1,
        "node": chosen or "finish",
        "tool": NODE_TOOL.get(chosen, ""),
        "source": routing_source,
        "reason": routing_reason or routing_error,
        "confidence": routing_confidence,
    }
    router_update = _update(state, "router", "done", summary)
    node_status.update(router_update["node_status"])
    execution_trace.extend(router_update["execution_trace"])
    return {
        "current_node": "router",
        "node_status": node_status,
        "execution_trace": execution_trace,
        "routes": routes,
        "next_scan_node": next_node,
        "completed_scan_nodes": completed,
        "scan_decisions": [decision_record],
        "routing_mode": routing_mode,
        "routing_reason": routing_reason or routing_error,
        "routing_confidence": routing_confidence,
        "routing_error": routing_error,
    }


def node_web_scan(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "web_scan", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    urls = [
        str(item.get("url"))
        for item in state.get("live_endpoints", [])
        if item.get("url")
    ]
    if not urls:
        return _skipped_reason(state, "web_scan", "no_http_endpoints")
    adapter = _adapter(ZapAdapter, state, "web_scan")
    if not adapter.available():
        return _skipped(state, "web_scan", "zap")
    try:
        options = _scope_options(state)
        with _exclusive_file_lock(
            os.path.join(settings.output_dir, "zap-active-scan.lock")
        ):
            findings = adapter.run(urls, options)
        return {
            **_update(state, "web_scan", "done", f"{len(findings)} ZAP findings"),
            "vuln_findings": _as_dicts(findings),
            **(
                {"auth_metrics": options.get("auth_metrics", {})}
                if options.get("auth_metrics")
                else {}
            ),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "web_scan", "zap", exc, locals().get("options"))


def node_nuclei_scan(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "nuclei_scan", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    urls = [str(item.get("url")) for item in state.get("live_endpoints", []) if item.get("url")]
    if not urls:
        return _skipped_reason(state, "nuclei_scan", "no_http_endpoints")
    adapter = _adapter(NucleiAdapter, state, "nuclei_scan")
    if not adapter.available():
        return _skipped(state, "nuclei_scan", "nuclei")
    try:
        options = _scope_options(state)
        findings = adapter.run(urls, options)
        return {
            **_update(state, "nuclei_scan", "done", f"{len(findings)} Nuclei findings"),
            "vuln_findings": _as_dicts(findings),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "nuclei_scan", "nuclei", exc, locals().get("options"))


def node_js_secret_scan(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "js_secret_scan", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    urls = [
        str(item.get("url"))
        for item in state.get("live_endpoints", [])
        if str(item.get("url", "")).lower().split("?", 1)[0].endswith(".js")
    ]
    if not urls:
        return _skipped_reason(state, "js_secret_scan", "no_javascript_assets")
    adapter = _adapter(GitleaksAdapter, state, "js_secret_scan")
    if not adapter.available():
        return _skipped(state, "js_secret_scan", "gitleaks")
    try:
        options = _scope_options(state)
        findings = adapter.run(urls, options)
        return {
            **_update(state, "js_secret_scan", "done", f"{len(findings)} secrets"),
            "secret_findings": _as_dicts(findings),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "js_secret_scan", "gitleaks", exc, locals().get("options"))


def node_api_fuzz(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "api_fuzz", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    urls = [
        str(item.get("url"))
        for item in state.get("live_endpoints", [])
        if any(token in str(item.get("url", "")).lower() for token in ("swagger", "openapi"))
    ]
    if not urls:
        return _skipped_reason(state, "api_fuzz", "no_openapi_contract")
    adapter = _adapter(SchemathesisAdapter, state, "api_fuzz")
    if not adapter.available():
        return _skipped(state, "api_fuzz", "schemathesis")
    try:
        options = _scope_options(state)
        findings = adapter.run(urls, options)
        return {
            **_update(state, "api_fuzz", "done", f"{len(findings)} API findings"),
            "api_findings": _as_dicts(findings),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "api_fuzz", "schemathesis", exc, locals().get("options"))


def node_k8s_audit(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "k8s_audit", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    ports = {item.get("port") for item in state.get("port_findings", [])}
    if 6443 not in ports:
        return _skipped_reason(state, "k8s_audit", "k8s_route_not_selected")
    adapter = _adapter(KubescapeAdapter, state, "k8s_audit")
    if not adapter.available():
        return _skipped(state, "k8s_audit", "kubescape")
    if not os.getenv("KUBECONFIG"):
        return _skipped_reason(
            state,
            "k8s_audit",
            "kubescape_requires_kubeconfig",
        )
    try:
        options = _scope_options(state)
        findings = adapter.run(state["target"], options)
        return {
            **_update(state, "k8s_audit", "done", f"{len(findings)} K8s findings"),
            "k8s_findings": _as_dicts(findings),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "k8s_audit", "kubescape", exc, locals().get("options"))


def node_server_baseline(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "server_baseline", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    urls = _unique_origins(
        [
            str(item.get("url"))
            for item in state.get("live_endpoints", [])
            if item.get("url")
        ]
    )
    if not urls:
        return _skipped_reason(state, "server_baseline", "no_http_endpoints")
    findings: list[Finding] = []
    tools = []
    errors: list[str] = []
    options = _scope_options(state)
    nikto = _adapter(NiktoAdapter, state, "server_baseline")
    profile = state.get("tool_profile", "full_agent")
    if profile == "full_agent" and nikto.available():
        tools.append("nikto")
        try:
            findings.extend(nikto.run(urls, options))
        except AdapterCancelled:
            raise
        except Exception as exc:
            errors.append(redact_text(f"nikto: {exc}"))
    wapiti = _adapter(WapitiAdapter, state, "server_baseline")
    if wapiti.available():
        tools.append("wapiti")
        try:
            findings.extend(wapiti.run(urls, options))
            if (
                options.get("auth_scan")
                and options.get("auth_metrics", {}).get("wapiti_authenticated") is False
            ):
                errors.append("wapiti_authentication_failed")
        except AdapterCancelled:
            raise
        except Exception as exc:
            errors.append(redact_text(f"wapiti: {exc}"))
    if not tools:
        return _skipped(state, "server_baseline", "nikto+wapiti")
    status = "failed" if len(errors) == len(tools) else "done"
    return {
        **_update(
            state,
            "server_baseline",
            status,
            f"{len(findings)} baseline findings",
            "; ".join(errors) if errors else None,
        ),
        "vuln_findings": _as_dicts(findings),
        **(
            {
                "auth_metrics": {
                    **(state.get("auth_metrics") or {}),
                    **(options.get("auth_metrics") or {}),
                }
            }
            if options.get("auth_metrics")
            else {}
        ),
        **_blocked_update(options),
        **({"errors": errors} if errors else {}),
    }


def node_active_validation(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "active_validation", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    if state.get("validation_level", "safe") == "off":
        return _skipped_reason(state, "active_validation", "validation_disabled")
    urls = _validation_seeds(state)
    if not urls:
        return _skipped_reason(state, "active_validation", "no_http_endpoints")
    adapter = _adapter(ActiveValidationAdapter, state, "active_validation")
    try:
        options = _scope_options(state)
        findings = adapter.run(urls, options)
        errors = [
            redact_text(str(item))
            for item in options.get("errors", [])
            if str(item).strip()
        ]
        return {
            **_update(
                state,
                "active_validation",
                "done",
                f"{len(findings)} validated findings",
                "; ".join(errors) if errors else None,
                record_error=False,
            ),
            "vuln_findings": _as_dicts(findings),
            **_blocked_update(options),
            **({"errors": errors} if errors else {}),
        }
    except Exception as exc:
        return _exception_update(
            state,
            "active_validation",
            "safe-validators",
            exc,
            locals().get("options"),
        )


def node_host_vuln_scan(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return {
            **_update(state, "host_vuln_scan", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    if state.get("mode") != "full":
        return _skipped_reason(state, "host_vuln_scan", "full_mode_disabled")
    adapter = _adapter(OpenvasAdapter, state, "host_vuln_scan")
    if not adapter.available():
        return _skipped(state, "host_vuln_scan", "openvas")
    try:
        options = _scope_options(state)
        findings = adapter.run(state["target"], options)
        return {
            **_update(state, "host_vuln_scan", "done", f"{len(findings)} GVM findings"),
            "vuln_findings": _as_dicts(findings),
            **_blocked_update(options),
        }
    except Exception as exc:
        return _exception_update(state, "host_vuln_scan", "openvas", exc, locals().get("options"))


def node_merge_and_score(state: PentestState) -> dict[str, Any]:
    if cancel_requested():
        return {
            **_update(state, "merge_and_score", "skipped", "cancelled"),
            "status": "cancelled",
            "cancelled": True,
        }
    rows: list[Finding] = []
    for key in (
        "takeover_findings",
        "port_findings",
        "vuln_findings",
        "api_findings",
        "k8s_findings",
        "secret_findings",
    ):
        for item in state.get(key, []):
            try:
                rows.append(Finding.model_validate(item))
            except Exception:
                continue
    merged = merge_findings(rows)
    store = EvidenceStore(settings.output_dir, state["task_id"])
    for item in merged:
        item.evidence = redact(item.evidence)
        item.raw = redact(item.raw)
        item.evidence_hash = item.compute_evidence_hash()
        filename, _ = playbook_for(item.vuln_type)
        item.playbook = filename or None
        store.write(item)
    store.write_index(merged)
    finding_dicts = [item.model_dump() for item in merged]
    groups = build_risk_groups(finding_dicts)
    benchmark = evaluate_lab_benchmark(state["target"], finding_dicts)
    memory = complete_memory_context(
        state.get("memory_context") or {},
        finding_dicts,
        groups,
    )
    return {
        **_update(
            state,
            "merge_and_score",
            "done",
            f"unique findings: {len(merged)}",
        ),
        "findings": finding_dicts,
        "risk_groups": groups,
        "benchmark_context": benchmark,
        "memory_context": memory,
    }


def node_llm_summarize(state: PentestState) -> dict[str, Any]:
    if state.get("cancelled") or cancel_requested():
        return _skipped_reason(state, "llm_summarize", "cancelled")
    db = None
    try:
        db = SessionLocal()
        config = load_ai_config(db)
    except Exception:
        if db is not None:
            db.close()
        db = None
        config = load_ai_config(None)
    if not config.enabled:
        if db is not None:
            db.close()
        return _skipped_reason(state, "llm_summarize", "llm_disabled")
    if not config.base_url or not config.model:
        if db is not None:
            db.close()
        return _skipped_reason(state, "llm_summarize", "llm_not_configured")
    try:
        groups, summary = analyze_risk_groups(
            db,
            state.get("risk_groups") or [],
            state.get("memory_context") or {},
            config,
        )
        text = str(summary.get("text") or "").strip()
        if not text:
            return _skipped_reason(state, "llm_summarize", "llm_empty_response")
        return {
            **_update(
                state,
                "llm_summarize",
                "done",
                (
                    "AI risk groups generated with degraded batches"
                    if summary.get("degraded_batches")
                    else "AI risk groups and interpretation generated"
                ),
            ),
            "risk_groups": groups,
            "llm_summary": {
                "enabled": True,
                "model": config.model,
                "text": redact_text(text),
                "summary_en": redact_text(str(summary.get("summary_en") or "")),
                "cached": bool(summary.get("cached")),
                "batches": int(summary.get("batches") or 0),
                "degraded_batches": summary.get("degraded_batches") or [],
            },
        }
    except Exception as exc:
        return _skipped_reason(
            state,
            "llm_summarize",
            f"llm_degraded: {redact_text(str(exc))}",
        )
    finally:
        if db is not None:
            db.close()


def node_report(state: PentestState) -> dict[str, Any]:
    findings = [Finding.model_validate(item) for item in state.get("findings", [])]
    if state.get("cancelled") or state.get("status") == "cancelled":
        status = "cancelled"
    elif state.get("status") in {"blocked", "failed"}:
        status = str(state["status"])
    elif state.get("status") == "partial":
        status = "partial"
    else:
        status = "completed"
    completed_at = _now()
    report_node_status = {**state.get("node_status", {}), "report": "done"}
    report_trace = list(state.get("execution_trace", []))
    report_trace.append(
        {
            "node_name": "report",
            "tool_name": NODE_TOOL["report"],
            "started_at": completed_at,
            "finished_at": completed_at,
            "status": "done",
            "output_summary": "report ready",
            "error": None,
        }
    )
    report_result = render_report(
        task_id=state["task_id"],
        target=state["target"],
        status=status,
        findings=findings,
        node_status=report_node_status,
        trace=report_trace,
        output_dir=settings.output_dir,
        llm_summary=state.get("llm_summary") or {},
        blocked_targets=state.get("blocked_targets") or [],
        risk_groups=state.get("risk_groups") or [],
        memory_context=state.get("memory_context") or {},
        budget_context={
            "validation_level": state.get("validation_level"),
            "oast_enabled": bool(state.get("oast_enabled")),
        },
        routing_context={
            "mode": state.get("routing_mode") or "auto",
            "reason": state.get("routing_reason") or "",
            "confidence": int(state.get("routing_confidence") or 0),
            "completed_scan_nodes": state.get("completed_scan_nodes") or [],
            "decisions": state.get("scan_decisions") or [],
        },
        benchmark_context=state.get("benchmark_context") or {},
    )
    return {
        **_update(state, "report", "done", "report ready"),
        "status": status,
        "report_result": report_result,
    }


def _discover_common_endpoints(
    state: PentestState,
    endpoints: list[dict[str, Any]],
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    candidates = ("/swagger.json", "/openapi.json", "/v3/api-docs")
    discovered: list[dict[str, Any]] = []
    seen = {str(item.get("url") or "").rstrip("/") for item in endpoints}
    delay = 1.0 / max(1, int(state.get("max_rps", 5)))
    with httpx.Client(
        timeout=None,
        follow_redirects=False,
        headers={"User-Agent": "attack-surface-scanner/0.1"},
    ) as client:
        for endpoint in endpoints:
            parsed_base = urllib.parse.urlparse(str(endpoint.get("url") or ""))
            if not parsed_base.scheme or not parsed_base.netloc:
                continue
            base = f"{parsed_base.scheme}://{parsed_base.netloc}"
            for path in candidates:
                candidate = f"{base}{path}"
                if candidate in seen:
                    continue
                try:
                    response = client.get(candidate)
                    time.sleep(delay)
                except httpx.HTTPError:
                    continue
                for _ in range(5):
                    if not response.is_redirect:
                        break
                    next_url = urllib.parse.urljoin(
                        str(response.url),
                        response.headers.get("location", ""),
                    )
                    try:
                        validate_scope(
                            next_url,
                            options.get("scope", []),
                            options.get("allowed_cidrs", []),
                        )
                    except GuardError as exc:
                        blocked = options.setdefault("blocked_targets", [])
                        blocked.append(f"{exc}: {next_url}")
                        response = None
                        break
                    response = client.get(next_url)
                if response is None:
                    continue
                if response.status_code >= 400:
                    continue
                content_type = response.headers.get("content-type", "").lower()
                body = response.text[:4096].lower()
                if "json" not in content_type and '"openapi"' not in body and '"swagger"' not in body:
                    continue
                seen.add(candidate)
                discovered.append(
                    {
                        "url": candidate,
                        "host": urllib.parse.urlparse(candidate).hostname or endpoint.get("host", ""),
                        "port": urllib.parse.urlparse(candidate).port,
                        "status_code": response.status_code,
                        "title": "OpenAPI discovery",
                        "tech": ["openapi"],
                    }
                )
                try:
                    payload = response.json()
                except ValueError:
                    payload = {}
                for server in payload.get("servers", []) if isinstance(payload, dict) else []:
                    raw_server = str(server.get("url") or "")
                    server_url = urllib.parse.urljoin(candidate, raw_server)
                    if not server_url or server_url.startswith("/"):
                        continue
                    try:
                        validate_scope(
                            server_url,
                            options.get("scope", []),
                            options.get("allowed_cidrs", []),
                        )
                    except GuardError as exc:
                        blocked = options.setdefault("blocked_targets", [])
                        blocked.append(f"{exc}: {server_url}")
                        continue
                    discovered.append(
                        {
                            "url": server_url,
                            "host": urllib.parse.urlparse(server_url).hostname or "",
                            "port": urllib.parse.urlparse(server_url).port,
                            "status_code": response.status_code,
                            "title": "OpenAPI server",
                            "tech": ["openapi"],
                        }
                    )
    return discovered


_SCRIPT_SOURCE_RE = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_ANCHOR_HREF_RE = re.compile(
    r"""<a\b[^>]*\bhref\s*=\s*["']([^"'#][^"']*)["']""",
    re.IGNORECASE,
)
_JS_ENDPOINT_RE = re.compile(
    r"""(?P<path>/?(?:rest|api|ftp|socket\.io)/[^`'"\s<>]{1,180})""",
    re.IGNORECASE,
)


def _discover_client_assets(
    state: PentestState,
    endpoints: list[dict[str, Any]],
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    origins: list[str] = []
    for endpoint in endpoints:
        parsed = urllib.parse.urlparse(str(endpoint.get("url") or ""))
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin not in origins:
                origins.append(origin)
    if not origins:
        return []

    try:
        session = authenticate(str(options.get("auth_ref") or "")) if options.get("auth_scan") else None
    except Exception:
        session = None
    headers = {
        "User-Agent": "attack-surface-scanner/0.1",
        **(session.request_headers() if session else {}),
    }
    discovered: list[dict[str, Any]] = []
    seen: set[str] = set()
    delay = 1.0 / max(1, int(state.get("max_rps", 5)))

    def add(url: str, *, title: str, tech: list[str]) -> bool:
        normalized = str(url).strip()
        if not normalized or normalized in seen:
            return False
        try:
            validate_scope(
                normalized,
                options.get("scope", []),
                options.get("allowed_cidrs", []),
            )
        except GuardError as exc:
            options.setdefault("blocked_targets", []).append(f"{exc}: {normalized}")
            return False
        parsed = urllib.parse.urlparse(normalized)
        seen.add(normalized)
        discovered.append(
            {
                "url": normalized,
                "host": parsed.hostname or "",
                "port": parsed.port,
                "status_code": None,
                "title": title,
                "tech": tech,
            }
        )
        return True

    with httpx.Client(
        timeout=None,
        follow_redirects=True,
        headers=headers,
    ) as client:
        for origin in origins[:3]:
            try:
                page = client.get(origin)
            except httpx.HTTPError:
                continue
            time.sleep(delay)
            if page.status_code >= 400:
                continue
            scripts = [
                urllib.parse.urljoin(str(page.url), value)
                for value in _SCRIPT_SOURCE_RE.findall(page.text)
            ]
            links = [
                urllib.parse.urljoin(str(page.url), value)
                for value in _ANCHOR_HREF_RE.findall(page.text)
            ]
            for script in scripts[:12]:
                add(script, title="JavaScript asset", tech=["javascript"])
            for link in links[:30]:
                add(
                    link.split("#", 1)[0],
                    title="Client-side link",
                    tech=["spa_route"],
                )
            for script in scripts[:8]:
                try:
                    asset = client.get(script)
                except httpx.HTTPError:
                    continue
                time.sleep(delay)
                if asset.status_code >= 400:
                    continue
                for match in _JS_ENDPOINT_RE.finditer(asset.text):
                    raw_path = match.group("path").split("${", 1)[0]
                    raw_path = raw_path.rstrip("\\,);")
                    if not raw_path or raw_path.endswith(("/", ".")):
                        continue
                    candidate = urllib.parse.urljoin(origin, raw_path)
                    add(
                        candidate,
                        title="JavaScript API route",
                        tech=["spa_route", "api"],
                    )
                    if len(discovered) >= 80:
                        return discovered
    return discovered
