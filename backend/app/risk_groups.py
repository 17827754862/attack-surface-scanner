from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any

from .i18n import severity_labels, vuln_type_labels
from .playbooks import playbook_for


SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

TYPE_DETAIL_KEYS = {
    "information_disclosure",
    "sensitive_file_exposure",
}


def _detail_key(finding: dict[str, Any], canonical: str) -> str:
    if canonical not in TYPE_DETAIL_KEYS:
        return ""
    raw = finding.get("raw") if isinstance(finding.get("raw"), dict) else {}
    for key in ("pluginId", "template-id", "alert", "id"):
        value = raw.get(key)
        if value not in (None, ""):
            return str(value).strip().lower()
    return str(finding.get("vuln_type") or "").strip().lower()


def _group_key(finding: dict[str, Any], canonical: str) -> str:
    payload = {
        "host": str(finding.get("host") or "").lower(),
        "port": finding.get("port"),
        "vuln_type": canonical,
        "detail": _detail_key(finding, canonical),
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def build_risk_groups(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for finding in findings:
        canonical = str(finding.get("vuln_type") or "unknown")
        key = _group_key(finding, canonical)
        group = grouped.get(key)
        if group is None:
            title_zh, title_en = vuln_type_labels(canonical)
            group = {
                "key": key,
                "vuln_type": canonical,
                "title_zh": title_zh,
                "title_en": title_en,
                "host": finding.get("host") or "",
                "port": finding.get("port"),
                "severity": finding.get("severity") or "info",
                "confidence": int(finding.get("confidence") or 0),
                "sources": [],
                "affected_urls": [],
                "fingerprints": [],
                "instances": [],
                "description_zh": "",
                "description_en": "",
                "impact_zh": "",
                "impact_en": "",
                "reproduction_steps_zh": [],
                "reproduction_steps_en": [],
                "false_positive_checks_zh": [],
                "false_positive_checks_en": [],
                "remediation_zh": [],
                "remediation_en": [],
                "retest_steps_zh": [],
                "retest_steps_en": [],
                "analysis_source": "deterministic",
                "ai_confidence": None,
            }
            grouped[key] = group
        if SEVERITY_RANK.get(str(finding.get("severity")), 0) > SEVERITY_RANK.get(
            str(group.get("severity")), 0
        ):
            group["severity"] = finding.get("severity")
        group["confidence"] = max(
            int(group.get("confidence") or 0),
            int(finding.get("confidence") or 0),
        )
        for source in {
            str(finding.get("source") or ""),
            *[str(item) for item in finding.get("also_reported_by") or []],
        }:
            if source and source not in group["sources"]:
                group["sources"].append(source)
        url = str(finding.get("url") or "")
        if url and url not in group["affected_urls"]:
            group["affected_urls"].append(url)
        fingerprint = str(finding.get("fingerprint") or "")
        if fingerprint and fingerprint not in group["fingerprints"]:
            group["fingerprints"].append(fingerprint)
        group["instances"].append(
            {
                "fingerprint": fingerprint,
                "url": url,
                "source": finding.get("source"),
                "severity": finding.get("severity"),
                "evidence": finding.get("evidence") or {},
            }
        )

    for group in grouped.values():
        filename, _ = playbook_for(str(group["vuln_type"]))
        group["playbook"] = filename or None
        group["instance_count"] = len(group["fingerprints"])
        group["affected_url_count"] = len(group["affected_urls"])
        group["sources"].sort()
        group["affected_urls"].sort()

    return sorted(
        grouped.values(),
        key=lambda item: (
            SEVERITY_RANK.get(str(item.get("severity")), 0),
            int(item.get("confidence") or 0),
        ),
        reverse=True,
    )


def risk_type_summary(groups: list[dict[str, Any]]) -> list[str]:
    return sorted({str(item.get("vuln_type") or "") for item in groups if item.get("vuln_type")})


def severity_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        counts[str(finding.get("severity") or "info")] += 1
    return dict(counts)
