from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


def merge_dicts(
    left: dict[str, Any] | None,
    right: dict[str, Any] | None,
) -> dict[str, Any]:
    return {**(left or {}), **(right or {})}


def take_last(_left: Any, right: Any) -> Any:
    return right


def merge_status(left: str | None, right: str | None) -> str | None:
    priority = {
        None: 0,
        "pending": 1,
        "queued": 2,
        "running": 3,
        "resuming": 3,
        "partial": 4,
        "completed": 4,
        "partial": 5,
        "cancelled": 6,
        "failed": 7,
        "blocked": 8,
    }
    return right if priority.get(right, 0) >= priority.get(left, 0) else left


def first_value(left: Any, right: Any) -> Any:
    return left if left not in (None, "") else right


class PentestState(TypedDict, total=False):
    task_id: str
    target: str
    auth_ref: str
    scope: list[str]
    allowed_cidrs: list[str]
    resolved_ips: list[str]
    max_rps: int
    mode: str
    tool_profile: str
    validation_level: str
    oast_enabled: bool
    status: Annotated[str, merge_status]

    subdomains: list[str]
    resolved_hosts: list[str]
    live_endpoints: Annotated[list[dict[str, Any]], operator.add]
    port_findings: Annotated[list[dict[str, Any]], operator.add]
    vuln_findings: Annotated[list[dict[str, Any]], operator.add]
    api_findings: Annotated[list[dict[str, Any]], operator.add]
    k8s_findings: Annotated[list[dict[str, Any]], operator.add]
    secret_findings: Annotated[list[dict[str, Any]], operator.add]
    takeover_findings: Annotated[list[dict[str, Any]], operator.add]
    findings: list[dict[str, Any]]

    execution_trace: Annotated[list[dict[str, Any]], operator.add]
    current_node: Annotated[str, take_last]
    node_status: Annotated[dict[str, str], merge_dicts]
    errors: Annotated[list[str], operator.add]
    blocked_targets: Annotated[list[str], operator.add]
    cancelled: Annotated[bool, operator.or_]
    resume_from: Annotated[str | None, first_value]
    capabilities: dict[str, dict[str, Any]]
    routes: list[str]
    next_scan_node: str
    completed_scan_nodes: list[str]
    scan_decisions: Annotated[list[dict[str, Any]], operator.add]
    routing_mode: str
    routing_reason: str
    routing_confidence: int
    routing_error: str
    llm_summary: dict[str, Any]
    risk_groups: list[dict[str, Any]]
    benchmark_context: dict[str, Any]
    memory_context: dict[str, Any]
    auth_metrics: dict[str, Any]
    report_result: dict[str, Any]
    resuming: bool
