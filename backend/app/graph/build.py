from __future__ import annotations

from typing import Any, Callable

from langgraph.graph import END, START, StateGraph

from . import nodes
from ..adapters.base import AdapterCancelled
from .edges import route_after_auth, route_after_router
from .state import PentestState


def build_graph(
    checkpointer: Any = None,
    event_sink: Callable[[dict[str, Any]], None] | None = None,
    start_at: str | None = None,
):
    graph = StateGraph(PentestState)

    def wrap(name: str, fn):
        def wrapped(state: PentestState) -> dict[str, Any]:
            working_state = dict(state)
            if event_sink:
                event_sink(
                    {
                        "node": name,
                        "event": "on_chain_start",
                        "tool": nodes.NODE_TOOL.get(name, ""),
                    }
                )
            if (
                state.get("resuming")
                and name in nodes.SCAN_NODES
                and (state.get("node_status") or {}).get(name) == "done"
            ):
                output = {
                    "current_node": name,
                    "execution_trace": [
                        {
                            "node_name": name,
                            "tool_name": nodes.NODE_TOOL.get(name, ""),
                            "status": "done",
                            "output_summary": "reused completed checkpoint",
                            "error": None,
                        }
                    ],
                }
            elif (
                name in nodes.SCAN_NODES
                and state.get("routes") is not None
                and name not in (state.get("routes") or [])
            ):
                output = {
                    "current_node": name,
                    "node_status": {name: "skipped"},
                    "execution_trace": [
                        {
                            "node_name": name,
                            "tool_name": nodes.NODE_TOOL.get(name, ""),
                            "status": "skipped",
                            "output_summary": "",
                            "error": "route_not_selected",
                        }
                    ],
                }
            elif nodes.cancel_requested() and name not in {
                "merge_and_score",
                "llm_summarize",
                "report",
            }:
                output = {
                    "current_node": name,
                    "node_status": {name: "skipped"},
                    "execution_trace": [
                        {
                            "node_name": name,
                            "tool_name": nodes.NODE_TOOL.get(name, ""),
                            "status": "skipped",
                            "output_summary": "cancelled",
                            "error": "task_cancelled",
                        }
                    ],
                    "status": "cancelled",
                    "cancelled": True,
                    "resume_from": state.get("resume_from") or name,
                }
            else:
                try:
                    output = fn(working_state)
                except AdapterCancelled as exc:
                    output = {
                        "current_node": name,
                        "node_status": {name: "failed"},
                        "execution_trace": [
                            {
                                "node_name": name,
                                "tool_name": nodes.NODE_TOOL.get(name, ""),
                                "status": "failed",
                                "output_summary": "cancelled",
                                "error": str(exc),
                            }
                        ],
                        "errors": [f"{name}: {exc}"],
                        "status": "cancelled",
                        "cancelled": True,
                        "resume_from": name,
                    }
                except Exception as exc:
                    error = f"{name}: {exc}"
                    output = {
                        "current_node": name,
                        "node_status": {name: "failed"},
                        "execution_trace": [
                            {
                                "node_name": name,
                                "tool_name": nodes.NODE_TOOL.get(name, ""),
                                "status": "failed",
                                "output_summary": "",
                                "error": error,
                            }
                        ],
                        "errors": [error],
                        "status": "failed",
                    }
            if event_sink:
                node_status = output.get("node_status", {})
                if (
                    any(value == "failed" for value in node_status.values())
                    and output.get("status") != "cancelled"
                ):
                    output["status"] = "failed"
                traces = {
                    str(item.get("node_name")): item
                    for item in output.get("execution_trace", [])
                    if item.get("node_name")
                }
                emitted: set[str] = set()
                for node_name, trace_entry in traces.items():
                    node_state = str(
                        trace_entry.get("status")
                        or node_status.get(node_name)
                        or "done"
                    )
                    event_sink(
                        {
                            "node": node_name,
                            "event": (
                                "on_chain_error"
                                if node_state == "failed"
                                else "on_chain_end"
                            ),
                            "tool": nodes.NODE_TOOL.get(node_name, ""),
                            "status": node_state,
                            "summary": trace_entry.get("output_summary", ""),
                            "error": trace_entry.get("error"),
                        }
                    )
                    emitted.add(node_name)
                for node_name, node_state in node_status.items():
                    if node_name in emitted:
                        continue
                    event_sink(
                        {
                            "node": node_name,
                            "event": (
                                "on_chain_error"
                                if node_state == "failed"
                                else "on_chain_end"
                            ),
                            "tool": nodes.NODE_TOOL.get(node_name, ""),
                            "status": node_state,
                            "summary": "",
                            "error": None,
                        }
                    )
            return output

        return wrapped

    node_functions = {
        "auth_gate": nodes.node_auth_gate,
        "recon": nodes.node_recon,
        "dns_resolve": nodes.node_dns_resolve,
        "takeover_check": nodes.node_takeover_check,
        "http_probe": nodes.node_http_probe,
        "port_scan": nodes.node_port_scan,
        "credential_session_analysis": nodes.node_credential_session_analysis,
        "router": nodes.node_router,
        "web_scan": nodes.node_web_scan,
        "nuclei_scan": nodes.node_nuclei_scan,
        "js_secret_scan": nodes.node_js_secret_scan,
        "api_fuzz": nodes.node_api_fuzz,
        "k8s_audit": nodes.node_k8s_audit,
        "server_baseline": nodes.node_server_baseline,
        "active_validation": nodes.node_active_validation,
        "host_vuln_scan": nodes.node_host_vuln_scan,
        "merge_and_score": nodes.node_merge_and_score,
        "llm_summarize": nodes.node_llm_summarize,
        "report": nodes.node_report,
    }
    for name, fn in node_functions.items():
        graph.add_node(name, wrap(name, fn))

    resume_targets: list[str]
    if start_at:
        resume_targets = [start_at]
    else:
        resume_targets = ["auth_gate"]
    for target in resume_targets:
        graph.add_edge(START, target)
    graph.add_conditional_edges(
        "auth_gate",
        route_after_auth,
        {"recon": "recon", "report": "report"},
    )
    graph.add_edge("recon", "dns_resolve")
    graph.add_edge("dns_resolve", "takeover_check")
    graph.add_edge("takeover_check", "http_probe")
    graph.add_edge("http_probe", "port_scan")
    graph.add_edge("port_scan", "credential_session_analysis")
    graph.add_edge("credential_session_analysis", "router")
    graph.add_conditional_edges(
        "router",
        route_after_router,
        {
            **{name: name for name in nodes.SCAN_NODES},
            "merge_and_score": "merge_and_score",
        },
    )
    for scan_node in nodes.SCAN_NODES:
        graph.add_edge(scan_node, "router")
    graph.add_edge("merge_and_score", "llm_summarize")
    graph.add_edge("llm_summarize", "report")
    graph.add_edge("report", END)
    return graph.compile(checkpointer=checkpointer)
