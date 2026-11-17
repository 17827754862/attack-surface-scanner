from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from app.ai_service import apply_ai_analysis, choose_next_scan_node
from app.config import settings
from app.graph.nodes import node_llm_summarize


STATE = {
    "task_id": "llm",
    "target": "http://dvwa",
    "auth_ref": "local-dvwa",
    "node_status": {"llm_summarize": "pending"},
    "execution_trace": [],
    "findings": [
        {
            "severity": "high",
            "vuln_type": "sql_injection",
            "host": "dvwa",
            "confidence": 80,
        }
    ],
    "risk_groups": [
        {
            "key": "group-1",
            "vuln_type": "sql_injection",
            "title_zh": "SQL 注入",
            "title_en": "SQL Injection",
            "host": "dvwa",
            "port": 80,
            "severity": "high",
            "confidence": 80,
            "sources": ["zap"],
            "affected_urls": ["http://dvwa/item?id=1"],
            "fingerprints": ["fp-1"],
            "instances": [],
        }
    ],
    "memory_context": {"scan_count": 0},
}


def test_llm_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_enabled", False)
    result = node_llm_summarize(STATE)
    assert result["node_status"]["llm_summarize"] == "skipped"


def test_llm_summary_is_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_enabled", True)
    monkeypatch.setattr(settings, "llm_base_url", "http://llm/v1")
    monkeypatch.setattr(settings, "llm_api_key", "secret")
    monkeypatch.setattr(settings, "llm_model", "deepseek-chat")

    class Response:
        def raise_for_status(self): pass
        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"summary_zh":"先处置 SQL 注入，再复测。",'
                                '"summary_en":"Fix SQL injection first.",'
                                '"groups":[{"member_group_keys":["group-1"],'
                                '"title_zh":"SQL 注入","title_en":"SQL Injection",'
                                '"description_zh":"参数进入 SQL 查询。",'
                                '"description_en":"Input reaches SQL.",'
                                '"impact_zh":"可能读取数据库。","impact_en":"Database exposure.",'
                                '"reproduction_steps_zh":["复测原参数"],'
                                '"reproduction_steps_en":["Replay the original parameter"],'
                                '"false_positive_checks_zh":["检查响应差异"],'
                                '"false_positive_checks_en":["Check response differences"],'
                                '"remediation_zh":["使用参数化查询"],'
                                '"remediation_en":["Use parameterized queries"],'
                                '"retest_steps_zh":["重放原证据"],'
                                '"retest_steps_en":["Replay original evidence"],'
                                '"ai_confidence":88}]}'
                            )
                        }
                    }
                ]
            }

    monkeypatch.setattr("app.graph.nodes.httpx.post", lambda *_args, **_kwargs: Response())
    result = node_llm_summarize(STATE)
    assert result["llm_summary"]["text"].startswith("先处置")
    assert "findings" not in result
    assert result["risk_groups"][0]["analysis_source"] == "ai"


def test_llm_failure_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_enabled", True)
    monkeypatch.setattr(settings, "llm_base_url", "http://llm/v1")
    monkeypatch.setattr(settings, "llm_model", "deepseek-chat")
    monkeypatch.setattr(
        "app.graph.nodes.httpx.post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("token=secret")),
    )
    result = node_llm_summarize(STATE)
    assert result["node_status"]["llm_summarize"] == "skipped"
    assert "llm_degraded" in result["execution_trace"][0]["error"]


def test_ai_grouping_rejects_cross_type_merge() -> None:
    groups = [
        {
            "key": "a",
            "vuln_type": "sql_injection",
            "host": "dvwa",
            "port": 80,
            "severity": "high",
            "confidence": 80,
            "sources": ["zap"],
            "affected_urls": ["http://dvwa/a"],
            "fingerprints": ["a"],
            "instances": [],
        },
        {
            "key": "b",
            "vuln_type": "xss",
            "host": "dvwa",
            "port": 80,
            "severity": "medium",
            "confidence": 60,
            "sources": ["wapiti"],
            "affected_urls": ["http://dvwa/b"],
            "fingerprints": ["b"],
            "instances": [],
        },
    ]
    result = apply_ai_analysis(
        groups,
        {
            "groups": [
                {
                    "member_group_keys": ["a", "b"],
                    "title_zh": "错误合并",
                    "title_en": "Wrong merge",
                }
            ]
        },
    )
    assert len(result) == 2
    assert {item["key"] for item in result} == {"a", "b"}


def test_llm_analyzes_large_result_in_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "llm_enabled", True)
    monkeypatch.setattr(settings, "llm_base_url", "http://llm/v1")
    monkeypatch.setattr(settings, "llm_batch_size", 2)
    groups = []
    for index in range(5):
        groups.append(
            {
                "key": f"group-{index}",
                "vuln_type": "sql_injection",
                "host": "dvwa",
                "port": 80,
                "severity": "high",
                "confidence": 80,
                "sources": ["zap"],
                "affected_urls": [f"http://dvwa/item?id={index}"],
                "fingerprints": [f"fp-{index}"],
                "instances": [],
            }
        )
    state = {**STATE, "risk_groups": groups}
    calls: list[int] = []

    def fake_post(_url, **kwargs):
        calls.append(1)
        prompt = kwargs["json"]["messages"][0]["content"]
        keys = sorted(set(re.findall(r"group-\d+", prompt)))
        payload = {
            "summary_zh": "批量摘要",
            "summary_en": "Batch summary",
            "groups": [
                {
                    "member_group_keys": [key],
                    "title_zh": "SQL 注入",
                    "title_en": "SQL Injection",
                    "description_zh": "参数进入 SQL。",
                    "description_en": "Input reaches SQL.",
                    "ai_confidence": 80,
                }
                for key in keys
            ],
        }
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "choices": [
                    {"message": {"content": json.dumps(payload, ensure_ascii=False)}}
                ]
            },
        )

    monkeypatch.setattr("app.ai_service.httpx.post", fake_post)
    result = node_llm_summarize(state)
    assert result["node_status"]["llm_summarize"] == "done"
    assert result["llm_summary"]["batches"] == 3
    assert len(calls) == 3


def test_ai_router_only_accepts_candidate_nodes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.ai_service.httpx.post",
        lambda *_args, **_kwargs: SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "next_node": "nuclei_scan",
                                    "reason": "需要模板扫描补充证据",
                                    "confidence": 91,
                                },
                                ensure_ascii=False,
                            )
                        }
                    }
                ]
            },
        ),
    )
    config = SimpleNamespace(
        enabled=True,
        base_url="http://llm/v1",
        api_key="",
        model="deepseek-chat",
    )
    decision = choose_next_scan_node(
        candidates=["web_scan", "nuclei_scan"],
        context={"previous_scan": "web_scan", "findings": []},
        config=config,
    )
    assert decision["next_node"] == "nuclei_scan"
    assert decision["confidence"] == 91
