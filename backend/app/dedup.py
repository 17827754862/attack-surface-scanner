from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import settings
from .schemas.finding import Finding


SEVERITY_SCORE = {
    "info": 1.0,
    "low": 2.0,
    "medium": 3.0,
    "high": 4.0,
    "critical": 5.0,
}
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_SCORE)}


def score_finding(finding: Finding) -> float:
    return calculate_confidence(finding)


def _aliases() -> dict[str, str]:
    path = Path(settings.vuln_alias_file)
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        str(alias).strip().lower(): str(canonical)
        for canonical, values in payload.items()
        for alias in values
    }


def normalize_vuln_type(value: str) -> str:
    normalized = value.strip().lower()
    aliases = _aliases()
    if normalized in aliases:
        return aliases[normalized]
    for alias, canonical in aliases.items():
        if alias and alias in normalized:
            return canonical
    return normalized.replace(" ", "_").replace("-", "_")


def _exposure_score(finding: Finding) -> float:
    host = finding.host.lower()
    if host in {"localhost", "127.0.0.1", "dvwa", "mock"} or host.startswith("127."):
        return 25.0
    if host.startswith("10.") or host.startswith("192.168.") or host.startswith("172."):
        return 55.0
    if finding.url and finding.url.startswith("https://"):
        return 75.0
    return 100.0


def calculate_confidence(finding: Finding) -> float:
    source_count = 1 + len(set(finding.also_reported_by))
    source_score = min(100.0, source_count * 35.0)
    relevant = [
        finding.host,
        finding.url,
        finding.port,
        finding.evidence,
        finding.raw,
    ]
    evidence_score = 100.0 * sum(bool(item) for item in relevant) / len(relevant)
    severity_score = (SEVERITY_SCORE.get(finding.severity, 1.0) / 5.0) * 100.0
    confidence = (
        source_score * 0.30
        + evidence_score * 0.30
        + severity_score * 0.25
        + _exposure_score(finding) * 0.15
    )
    return round(max(0.0, min(100.0, confidence)), 2)


def merge_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        finding.vuln_type = normalize_vuln_type(finding.vuln_type)
        finding.fingerprint = finding.compute_fingerprint()
        fingerprint = finding.fingerprint or finding.compute_fingerprint()
        existing = merged.get(fingerprint)
        if existing is None:
            finding.score = score_finding(finding)
            merged[fingerprint] = finding
            continue
        if SEVERITY_RANK.get(finding.severity, 0) > SEVERITY_RANK.get(
            existing.severity, 0
        ):
            existing.severity = finding.severity
        for source in {finding.source, *finding.also_reported_by}:
            if source and source != existing.source and source not in existing.also_reported_by:
                existing.also_reported_by.append(source)
        existing_ids = {
            str(item)
            for item in existing.evidence.get("ground_truth_ids", [])
            if str(item).strip()
        }
        if existing.evidence.get("ground_truth_id"):
            existing_ids.add(str(existing.evidence["ground_truth_id"]))
        incoming_ids = {
            str(item)
            for item in finding.evidence.get("ground_truth_ids", [])
            if str(item).strip()
        }
        if finding.evidence.get("ground_truth_id"):
            incoming_ids.add(str(finding.evidence["ground_truth_id"]))
        if incoming_ids:
            merged_ids = sorted(existing_ids | incoming_ids)
            existing.evidence["ground_truth_ids"] = merged_ids
            existing.evidence.setdefault(
                "ground_truth_id",
                merged_ids[0],
            )
        existing.raw.setdefault("corroborating", []).append(
            {"source": finding.source, "evidence": finding.evidence}
        )
        existing.score = score_finding(existing)
    for finding in merged.values():
        finding.confidence = int(round(calculate_confidence(finding)))
        finding.score = float(finding.confidence)
    return sorted(
        merged.values(),
        key=lambda item: (
            item.confidence,
            SEVERITY_RANK.get(item.severity, 0),
        ),
        reverse=True,
    )


def findings_to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [item.model_dump() for item in findings]
