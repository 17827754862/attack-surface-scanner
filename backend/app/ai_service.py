from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .ai_config import AIRuntimeConfig
from .config import settings
from .db import AIAnalysisCache
from .redaction import redact, redact_text


def _endpoint(config: AIRuntimeConfig) -> str:
    return f"{config.base_url.rstrip('/')}/chat/completions"


def _headers(config: AIRuntimeConfig) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    return headers


def test_ai_connection(config: AIRuntimeConfig) -> dict[str, Any]:
    if not config.base_url or not config.model:
        raise ValueError("base_url and model are required")
    response = httpx.post(
        _endpoint(config),
        headers=_headers(config),
        json={
            "model": config.model,
            "messages": [
                {
                    "role": "user",
                    "content": "Reply with the single word OK.",
                }
            ],
            "temperature": 0,
            "max_tokens": 8,
        },
        timeout=None,
    )
    response.raise_for_status()
    payload = response.json()
    content = str(payload["choices"][0]["message"]["content"]).strip()
    return {"ok": True, "model": config.model, "response": redact_text(content[:100])}


def _parse_json_content(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        text = text.rsplit("```", 1)[0].strip()
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("AI response must be a JSON object")
    return payload


def _cache_key(groups: list[dict[str, Any]], memory: dict[str, Any], model: str) -> str:
    compact = [
        {
            "key": item.get("key"),
            "type": item.get("vuln_type"),
            "host": item.get("host"),
            "port": item.get("port"),
            "urls": item.get("affected_urls", [])[:20],
            "sources": item.get("sources"),
        }
        for item in groups[:100]
    ]
    encoded = json.dumps(
        {"groups": compact, "memory": memory, "model": model},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _prompt(groups: list[dict[str, Any]], memory: dict[str, Any]) -> str:
    compact = [
        {
            "group_key": item.get("key"),
            "vuln_type": item.get("vuln_type"),
            "host": item.get("host"),
            "port": item.get("port"),
            "severity": item.get("severity"),
            "confidence": item.get("confidence"),
            "sources": item.get("sources"),
            "affected_url_count": item.get("affected_url_count"),
            "sample_urls": (item.get("affected_urls") or [])[:5],
            "evidence_samples": [
                row.get("evidence")
                for row in (item.get("instances") or [])[:3]
            ],
        }
        for item in groups[:100]
    ]
    return (
        "你是授权安全评估项目中的防守侧分析器。请完成两件事：\n"
        "1. 对同一 host、port、vuln_type 的候选组做语义合并，只合并同一根因。\n"
        "2. 为每个最终风险组生成中英双语解读、低影响复现验证、误报检查、修复和复测建议。\n"
        "不得删除 Finding，不得修改原始证据，不得生成破坏性利用载荷、口令爆破或横向移动。\n"
        "只返回 JSON，不要 Markdown。格式：\n"
        '{"summary_zh":"...","summary_en":"...","groups":['
        '{"member_group_keys":["..."],"title_zh":"...","title_en":"...",'
        '"description_zh":"...","description_en":"...","impact_zh":"...","impact_en":"...",'
        '"reproduction_steps_zh":["..."],"reproduction_steps_en":["..."],'
        '"false_positive_checks_zh":["..."],"false_positive_checks_en":["..."],'
        '"remediation_zh":["..."],"remediation_en":["..."],'
        '"retest_steps_zh":["..."],"retest_steps_en":["..."],"ai_confidence":80}]}\n'
        f"历史记忆：{json.dumps(redact(memory), ensure_ascii=False)}\n"
        f"候选组：{json.dumps(compact, ensure_ascii=False)}"
    )


def choose_next_scan_node(
    *,
    candidates: list[str],
    context: dict[str, Any],
    config: AIRuntimeConfig,
) -> dict[str, Any]:
    if (
        not candidates
        or not config.enabled
        or not config.base_url
        or not config.model
    ):
        raise ValueError("AI routing is not configured")

    prompt = (
        "你是授权攻击面扫描器中的动态编排器。你只能从候选节点中选择下一个，"
        "不能生成命令、不能增加目标、不能绕过授权范围，也不能调用候选列表之外的工具。"
        "请根据已经完成的扫描结果决定哪一个工具最能补充当前证据。"
        "如果现有证据已经足够或继续扫描收益很低，可以返回 finish。"
        "只返回 JSON，不要 Markdown："
        '{"next_node":"候选节点或finish","reason":"不超过200字的中文理由",'
        '"confidence":0到100的整数}\n'
        f"候选节点：{json.dumps(candidates, ensure_ascii=False)}\n"
        f"当前状态：{json.dumps(redact(context), ensure_ascii=False)}"
    )
    response = httpx.post(
        _endpoint(config),
        headers=_headers(config),
        json={
            "model": config.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
            "max_tokens": 600,
        },
        timeout=None,
    )
    response.raise_for_status()
    payload = _parse_json_content(
        str(response.json()["choices"][0]["message"]["content"])
    )
    next_node = str(payload.get("next_node") or "").strip()
    if next_node not in {*candidates, "finish"}:
        raise ValueError(f"AI selected an invalid next node: {next_node!r}")
    return {
        "next_node": next_node,
        "reason": redact_text(str(payload.get("reason") or ""))[:500],
        "confidence": max(0, min(100, int(payload.get("confidence") or 0))),
    }


def analyze_risk_groups(
    db: Session | None,
    groups: list[dict[str, Any]],
    memory: dict[str, Any],
    config: AIRuntimeConfig,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not groups:
        return groups, {"text": "", "summary_en": "", "cached": False}
    batch_size = max(1, min(20, int(settings.llm_batch_size)))
    batches = [
        groups[index : index + batch_size]
        for index in range(0, len(groups), batch_size)
    ]
    output_groups: list[dict[str, Any]] = []
    summary_zh: list[str] = []
    summary_en: list[str] = []
    degraded_batches: list[int] = []
    cached_batches = 0
    for index, batch in enumerate(batches, start=1):
        key = _cache_key(batch, memory, config.model)
        cached = db.get(AIAnalysisCache, key) if db is not None else None
        if cached is not None:
            payload = dict(cached.payload or {})
            output_groups.extend(apply_ai_analysis(batch, payload))
            summary_zh.append(str(payload.get("summary_zh") or ""))
            summary_en.append(str(payload.get("summary_en") or ""))
            cached_batches += 1
            continue
        validated: dict[str, Any] | None = None
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = httpx.post(
                    _endpoint(config),
                    headers=_headers(config),
                    json={
                        "model": config.model,
                        "messages": [
                            {"role": "user", "content": _prompt(batch, memory)}
                        ],
                        "temperature": 0.1,
                        "max_tokens": max(512, int(settings.llm_max_tokens)),
                    },
                    timeout=None,
                )
                response.raise_for_status()
                candidate = _parse_json_content(
                    str(response.json()["choices"][0]["message"]["content"])
                )
                validated = _validate_ai_payload(batch, candidate)
                break
            except Exception as exc:
                last_error = exc
                if attempt == 0:
                    time.sleep(0.5)
        if validated is None:
            degraded_batches.append(index)
            output_groups.extend(batch)
            if last_error and len(batches) == 1:
                raise last_error
            continue
        if db is not None:
            db.add(
                AIAnalysisCache(
                    cache_key=key,
                    model=config.model,
                    payload=validated,
                )
            )
            db.commit()
        output_groups.extend(apply_ai_analysis(batch, validated))
        summary_zh.append(str(validated.get("summary_zh") or ""))
        summary_en.append(str(validated.get("summary_en") or ""))
    if len(degraded_batches) == len(batches):
        raise RuntimeError("all AI batches failed")
    output_groups.sort(
        key=lambda item: (
            {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
                str(item.get("severity")),
                0,
            ),
            int(item.get("confidence") or 0),
        ),
        reverse=True,
    )
    return output_groups, {
        "text": "\n".join(item for item in summary_zh if item),
        "summary_en": "\n".join(item for item in summary_en if item),
        "cached": cached_batches == len(batches),
        "batches": len(batches),
        "degraded_batches": degraded_batches,
    }


def _string(value: Any, limit: int = 4000) -> str:
    return redact_text(str(value or "").strip())[:limit]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_string(item) for item in value if _string(item)][:20]


def _validate_ai_payload(
    groups: list[dict[str, Any]],
    payload: dict[str, Any],
) -> dict[str, Any]:
    valid = {str(item.get("key")): item for item in groups}
    assigned: set[str] = set()
    output_groups = []
    for candidate in payload.get("groups") or []:
        if not isinstance(candidate, dict):
            continue
        member_keys = []
        for key in candidate.get("member_group_keys") or []:
            key = str(key)
            if key in valid and key not in assigned:
                member_keys.append(key)
                assigned.add(key)
        if not member_keys:
            continue
        members = [valid[key] for key in member_keys]
        if len({(item.get("host"), item.get("port"), item.get("vuln_type")) for item in members}) != 1:
            for key in member_keys:
                assigned.discard(key)
            continue
        output_groups.append(
            {
                "member_group_keys": member_keys,
                "title_zh": _string(candidate.get("title_zh"), 200),
                "title_en": _string(candidate.get("title_en"), 200),
                "description_zh": _string(candidate.get("description_zh")),
                "description_en": _string(candidate.get("description_en")),
                "impact_zh": _string(candidate.get("impact_zh")),
                "impact_en": _string(candidate.get("impact_en")),
                "reproduction_steps_zh": _string_list(candidate.get("reproduction_steps_zh")),
                "reproduction_steps_en": _string_list(candidate.get("reproduction_steps_en")),
                "false_positive_checks_zh": _string_list(candidate.get("false_positive_checks_zh")),
                "false_positive_checks_en": _string_list(candidate.get("false_positive_checks_en")),
                "remediation_zh": _string_list(candidate.get("remediation_zh")),
                "remediation_en": _string_list(candidate.get("remediation_en")),
                "retest_steps_zh": _string_list(candidate.get("retest_steps_zh")),
                "retest_steps_en": _string_list(candidate.get("retest_steps_en")),
                "ai_confidence": max(0, min(100, int(candidate.get("ai_confidence") or 0))),
            }
        )
    return {
        "summary_zh": _string(payload.get("summary_zh")),
        "summary_en": _string(payload.get("summary_en")),
        "groups": output_groups,
    }


def apply_ai_analysis(
    groups: list[dict[str, Any]],
    payload: dict[str, Any],
) -> list[dict[str, Any]]:
    by_key = {str(item.get("key")): dict(item) for item in groups}
    output: list[dict[str, Any]] = []
    assigned: set[str] = set()
    for analysis in payload.get("groups") or []:
        keys = [
            str(key)
            for key in analysis.get("member_group_keys") or []
            if str(key) in by_key and str(key) not in assigned
        ]
        if not keys:
            continue
        members = [by_key[key] for key in keys]
        if len(
            {
                (item.get("host"), item.get("port"), item.get("vuln_type"))
                for item in members
            }
        ) != 1:
            continue
        assigned.update(keys)
        merged = dict(members[0])
        merged["key"] = hashlib.sha256(":".join(sorted(keys)).encode("utf-8")).hexdigest()[:24]
        merged["affected_urls"] = sorted(
            {url for item in members for url in item.get("affected_urls") or []}
        )
        merged["fingerprints"] = sorted(
            {fp for item in members for fp in item.get("fingerprints") or []}
        )
        merged["sources"] = sorted(
            {source for item in members for source in item.get("sources") or []}
        )
        merged["instances"] = [
            instance for item in members for instance in item.get("instances") or []
        ]
        merged["affected_url_count"] = len(merged["affected_urls"])
        merged["instance_count"] = len(merged["fingerprints"])
        merged["severity"] = max(
            (item.get("severity") for item in members),
            key=lambda value: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
                str(value), 0
            ),
        )
        merged["confidence"] = max(int(item.get("confidence") or 0) for item in members)
        for field in (
            "title_zh",
            "title_en",
            "description_zh",
            "description_en",
            "impact_zh",
            "impact_en",
            "reproduction_steps_zh",
            "reproduction_steps_en",
            "false_positive_checks_zh",
            "false_positive_checks_en",
            "remediation_zh",
            "remediation_en",
            "retest_steps_zh",
            "retest_steps_en",
            "ai_confidence",
        ):
            if analysis.get(field) not in (None, "", []):
                merged[field] = analysis[field]
        merged["analysis_source"] = "ai"
        output.append(merged)
    output.extend(item for key, item in by_key.items() if key not in assigned)
    return sorted(
        output,
        key=lambda item: (
            {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
                str(item.get("severity")), 0
            ),
            int(item.get("confidence") or 0),
        ),
        reverse=True,
    )
