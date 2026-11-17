from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.graph import build as graph_build
from app.graph import nodes
from app.graph.build import build_graph
from app.graph.state import merge_status


def _base_state() -> dict:
    return {
        "task_id": "graph-test",
        "target": "http://dvwa",
        "auth_ref": "local-dvwa",
        "max_rps": 5,
        "mode": "active",
        "tool_profile": "full_agent",
        "status": "running",
        "subdomains": ["dvwa"],
        "resolved_hosts": ["dvwa"],
        "live_endpoints": [],
        "port_findings": [],
        "vuln_findings": [],
        "api_findings": [],
        "k8s_findings": [],
        "secret_findings": [],
        "takeover_findings": [],
        "findings": [],
        "execution_trace": [],
        "node_status": nodes.initial_node_status(),
        "errors": [],
        "blocked_targets": [],
        "cancelled": False,
        "routes": list(nodes.SCAN_NODES),
        "capabilities": {},
        "llm_summary": {},
        "report_result": {},
    }


def _fake_node(name: str):
    def fake(state):
        update = {
            "current_node": name,
            "node_status": {name: "done"},
            "execution_trace": [{"node_name": name, "status": "done"}],
        }
        if name == "auth_gate":
            update.update({"scope": ["dvwa"], "status": "running"})
        if name == "router":
            update["routes"] = list(nodes.SCAN_NODES)
            status = state.get("node_status") or {}
            update["next_scan_node"] = next(
                (
                    node
                    for node in nodes.SCAN_NODES
                    if status.get(node) != "done"
                ),
                "merge_and_score",
            )
        if name == "merge_and_score":
            update["findings"] = []
        return update

    return fake


def test_full_graph_mock_executes_all_nodes() -> None:
    names = list(graph_build.nodes.NODE_NAMES)
    old = {}
    for name in names:
        attr = f"node_{name}"
        old[attr] = getattr(graph_build.nodes, attr)
        setattr(graph_build.nodes, attr, _fake_node(name))
    try:
        graph = build_graph()
        result = graph.invoke(_base_state(), config={"recursion_limit": 64})
    finally:
        for attr, value in old.items():
            setattr(graph_build.nodes, attr, value)
    assert result["node_status"]["report"] == "done"
    assert result["node_status"]["llm_summarize"] == "done"
    for name in names:
        assert result["node_status"][name] == "done"


def test_resume_graph_from_scan_node() -> None:
    calls: list[str] = []

    def fake_nuclei(state):
        calls.append("nuclei")
        return {
            "current_node": "nuclei_scan",
            "node_status": {"nuclei_scan": "done"},
            "execution_trace": [{"node_name": "nuclei_scan", "status": "done"}],
        }

    def fake_merge(state):
        calls.append("merge")
        return {
            "current_node": "merge_and_score",
            "node_status": {"merge_and_score": "done"},
            "execution_trace": [],
            "findings": [],
        }

    def fake_llm(state):
        calls.append("llm")
        return {
            "current_node": "llm_summarize",
            "node_status": {"llm_summarize": "done"},
            "execution_trace": [],
        }

    def fake_report(state):
        calls.append("report")
        return {
            "current_node": "report",
            "node_status": {"report": "done"},
            "execution_trace": [],
            "status": "completed",
            "report_result": {},
        }

    def fake_router(_state):
        return {
            "current_node": "router",
            "node_status": {"router": "done"},
            "execution_trace": [],
            "routes": ["nuclei_scan"],
            "next_scan_node": "merge_and_score",
        }

    old = (
        nodes.node_nuclei_scan,
        nodes.node_router,
        nodes.node_merge_and_score,
        nodes.node_llm_summarize,
        nodes.node_report,
    )
    nodes.node_nuclei_scan = fake_nuclei
    nodes.node_router = fake_router
    nodes.node_merge_and_score = fake_merge
    nodes.node_llm_summarize = fake_llm
    nodes.node_report = fake_report
    try:
        graph = build_graph(start_at="nuclei_scan")
        state = _base_state()
        state["routes"] = ["nuclei_scan"]
        graph.invoke(state)
    finally:
        (
            nodes.node_nuclei_scan,
            nodes.node_router,
            nodes.node_merge_and_score,
            nodes.node_llm_summarize,
            nodes.node_report,
        ) = old
    assert calls == ["nuclei", "merge", "llm", "report"]


def test_node_router_honors_tool_profile_and_marks_exclusions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        nodes,
        "load_ai_config",
        lambda _db: SimpleNamespace(enabled=False, base_url="", model=""),
    )
    state = _base_state()
    state["live_endpoints"] = [{"url": "http://dvwa/index.php"}]
    state["port_findings"] = [{"port": 6443}]
    state["tool_profile"] = "nuclei"
    update = nodes.node_router(state)
    assert update["routes"] == ["nuclei_scan"]
    assert update["node_status"]["web_scan"] == "skipped"
    assert update["node_status"]["server_baseline"] == "skipped"
    assert update["node_status"]["k8s_audit"] == "skipped"
    assert update["node_status"]["host_vuln_scan"] == "skipped"
    assert update["routes"] == ["nuclei_scan"]
    assert update["next_scan_node"] == "nuclei_scan"
    assert update["routing_mode"] == "fixed"


def test_node_router_uses_ai_selection_from_candidate_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        nodes,
        "load_ai_config",
        lambda _db: SimpleNamespace(
            enabled=True,
            base_url="http://model.local/v1",
            model="test-model",
        ),
    )
    monkeypatch.setattr(
        nodes,
        "choose_next_scan_node",
        lambda **_kwargs: {
            "next_node": "nuclei_scan",
            "reason": "ZAP 结果需要模板扫描交叉验证",
            "confidence": 87,
        },
    )
    state = _base_state()
    state["live_endpoints"] = [{"url": "http://dvwa/index.php"}]
    update = nodes.node_router(state)
    assert update["next_scan_node"] == "nuclei_scan"
    assert update["routing_mode"] == "ai"
    assert update["routing_confidence"] == 87
    assert update["scan_decisions"][0]["source"] == "ai"


def test_parallel_status_updates_have_deterministic_priority() -> None:
    assert merge_status("running", "completed") == "completed"
    assert merge_status("completed", "cancelled") == "cancelled"
    assert merge_status("failed", "cancelled") == "failed"


def test_unselected_scan_branches_skip_without_breaking_join() -> None:
    calls: list[str] = []
    events: list[dict] = []

    def fake_router(_state):
        completed = (_state.get("node_status") or {}).get("nuclei_scan") == "done"
        return {
            "current_node": "router",
            "node_status": {
                "router": "done",
                **({"web_scan": "skipped"} if not completed else {}),
            },
            "execution_trace": [
                *([
                    {
                        "node_name": "web_scan",
                        "status": "skipped",
                        "output_summary": "",
                        "error": "condition_not_met",
                    }
                ] if not completed else []),
                {
                    "node_name": "router",
                    "status": "done",
                    "output_summary": "nuclei_scan",
                    "error": None,
                },
            ],
            "routes": ["nuclei_scan"],
            "next_scan_node": "merge_and_score" if completed else "nuclei_scan",
        }

    def fake_scan(name):
        def run(_state):
            calls.append(name)
            return {
                "current_node": name,
                "node_status": {name: "done"},
                "execution_trace": [],
            }

        return run

    def fake_merge(_state):
        calls.append("merge")
        return {
            "current_node": "merge_and_score",
            "node_status": {"merge_and_score": "done"},
            "execution_trace": [],
            "findings": [],
        }

    def fake_llm(_state):
        calls.append("llm")
        return {
            "current_node": "llm_summarize",
            "node_status": {"llm_summarize": "done"},
            "execution_trace": [],
        }

    def fake_report(_state):
        calls.append("report")
        return {
            "current_node": "report",
            "node_status": {"report": "done"},
            "execution_trace": [],
            "status": "completed",
            "report_result": {},
        }

    attrs = ["node_merge_and_score", "node_llm_summarize", "node_report"]
    old = {name: getattr(nodes, name) for name in attrs}
    old["node_router"] = nodes.node_router
    for name in attrs:
        setattr(
            nodes,
            name,
            {
                "node_merge_and_score": fake_merge,
                "node_llm_summarize": fake_llm,
                "node_report": fake_report,
            }[name],
        )
    nodes.node_router = fake_router
    for name in nodes.SCAN_NODES:
        attr = f"node_{name}"
        old[attr] = getattr(nodes, attr)
        setattr(nodes, attr, fake_scan(name))
    try:
        result = build_graph(
            start_at="router",
            event_sink=events.append,
        ).invoke(_base_state(), config={"recursion_limit": 64})
    finally:
        for attr, value in old.items():
            setattr(nodes, attr, value)
    assert calls == ["nuclei_scan", "merge", "llm", "report"]
    assert result["node_status"]["nuclei_scan"] == "done"
    assert result["node_status"]["web_scan"] == "skipped"
    assert result["node_status"]["report"] == "done"
    assert any(
        item["node"] == "web_scan"
        and item["status"] == "skipped"
        and item["error"] == "condition_not_met"
        for item in events
    )
