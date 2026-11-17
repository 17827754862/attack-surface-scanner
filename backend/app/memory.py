from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from .db import AssetSnapshot, Task
from .risk_groups import build_risk_groups, risk_type_summary, severity_summary


def asset_key(target: str) -> str:
    normalized = target.strip().rstrip("/").lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_memory_context(db: Session, target: str) -> dict[str, Any]:
    key = asset_key(target)
    rows = (
        db.query(AssetSnapshot)
        .filter(AssetSnapshot.asset_key == key)
        .order_by(AssetSnapshot.created_at.desc())
        .limit(10)
        .all()
    )
    if not rows:
        return {
            "asset_key": key,
            "scan_count": 0,
            "previous": None,
            "new_risk_types": [],
            "persistent_risk_types": [],
            "resolved_risk_types": [],
        }
    latest = rows[0]
    return {
        "asset_key": key,
        "scan_count": len(rows),
        "previous": {
            "task_id": latest.task_id,
            "scan_at": latest.created_at.isoformat(),
            "finding_count": latest.finding_count,
            "risk_group_count": latest.risk_group_count,
            "risk_types": latest.risk_types or [],
            "severity_counts": latest.severity_counts or {},
        },
        "new_risk_types": [],
        "persistent_risk_types": latest.risk_types or [],
        "resolved_risk_types": [],
    }


def complete_memory_context(
    context: dict[str, Any],
    findings: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> dict[str, Any]:
    previous = context.get("previous") or {}
    previous_types = set(previous.get("risk_types") or [])
    current_types = set(risk_type_summary(groups))
    return {
        **context,
        "current_finding_count": len(findings),
        "current_risk_group_count": len(groups),
        "current_risk_types": sorted(current_types),
        "new_risk_types": sorted(current_types - previous_types),
        "persistent_risk_types": sorted(current_types & previous_types),
        "resolved_risk_types": sorted(previous_types - current_types),
    }


def save_snapshot(
    db: Session,
    *,
    target: str,
    task_id: str,
    status: str,
    findings: list[dict[str, Any]],
    groups: list[dict[str, Any]],
) -> AssetSnapshot:
    existing = db.query(AssetSnapshot).filter(AssetSnapshot.task_id == task_id).one_or_none()
    if existing is None:
        existing = AssetSnapshot(
            asset_key=asset_key(target),
            target=target,
            task_id=task_id,
            status=status,
            finding_count=len(findings),
            risk_group_count=len(groups),
            severity_counts=severity_summary(findings),
            risk_types=risk_type_summary(groups),
            created_at=datetime.now().astimezone(),
        )
        db.add(existing)
    else:
        existing.status = status
        existing.finding_count = len(findings)
        existing.risk_group_count = len(groups)
        existing.severity_counts = severity_summary(findings)
        existing.risk_types = risk_type_summary(groups)
    db.commit()
    db.refresh(existing)
    return existing


def asset_history(db: Session, key: str, limit: int = 50) -> list[AssetSnapshot]:
    return (
        db.query(AssetSnapshot)
        .filter(AssetSnapshot.asset_key == key)
        .order_by(AssetSnapshot.created_at.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )


def list_assets(db: Session) -> list[dict[str, Any]]:
    rows = db.query(AssetSnapshot).order_by(AssetSnapshot.created_at.desc()).all()
    grouped: dict[str, list[AssetSnapshot]] = {}
    for row in rows:
        grouped.setdefault(row.asset_key, []).append(row)
    output = []
    for key, history in grouped.items():
        latest = history[0]
        previous = history[1] if len(history) > 1 else None
        output.append(
            {
                "asset_key": key,
                "target": latest.target,
                "scan_count": len(history),
                "latest_scan_at": latest.created_at.isoformat(),
                "latest_task_id": latest.task_id,
                "finding_count": latest.finding_count,
                "risk_group_count": latest.risk_group_count,
                "severity_counts": latest.severity_counts or {},
                "risk_types": latest.risk_types or [],
                "finding_delta": (
                    latest.finding_count - previous.finding_count if previous else latest.finding_count
                ),
                "previous_task_id": previous.task_id if previous else None,
            }
        )
    return sorted(output, key=lambda item: item["latest_scan_at"], reverse=True)


def total_snapshots(db: Session) -> int:
    return int(db.query(func.count(AssetSnapshot.id)).scalar() or 0)


def backfill_snapshots(db: Session) -> int:
    existing = {
        row[0]
        for row in db.query(AssetSnapshot.task_id).all()
    }
    created = 0
    for task in db.query(Task).order_by(Task.created_at.asc()).all():
        if task.id in existing or task.status not in {"completed", "failed", "cancelled"}:
            continue
        findings = list(task.findings or [])
        groups = list(task.risk_groups or [])
        if not groups and findings:
            groups = build_risk_groups(findings)
            task.risk_groups = groups
        save_snapshot(
            db,
            target=task.target,
            task_id=task.id,
            status=task.status,
            findings=findings,
            groups=groups,
        )
        created += 1
    return created
