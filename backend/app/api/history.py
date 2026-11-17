from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import Task, User, get_db
from ..memory import asset_history, list_assets, load_memory_context, total_snapshots
from ..security import get_current_user


router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("/tasks")
def task_history(
    limit: int = 100,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    rows = (
        db.query(Task)
        .order_by(Task.created_at.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    return {
        "count": len(rows),
        "items": [
            {
                "id": row.id,
                "target": row.target,
                "status": row.status,
                "mode": row.mode,
                "tool_profile": row.tool_profile,
                "findings_count": len(row.findings or []),
                "risk_group_count": len(row.risk_groups or []),
                "errors": row.errors or [],
                "created_at": row.created_at.isoformat(),
                "updated_at": row.updated_at.isoformat(),
            }
            for row in rows
        ],
    }


@router.get("/assets")
def asset_history_list(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    items = list_assets(db)
    return {
        "count": len(items),
        "snapshot_count": total_snapshots(db),
        "items": items,
    }


@router.get("/assets/{asset_key}")
def asset_history_detail(
    asset_key: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    rows = asset_history(db, asset_key, limit)
    if not rows:
        raise HTTPException(status_code=404, detail="asset history not found")
    latest = rows[0]
    memory = load_memory_context(db, latest.target)
    return {
        "asset_key": asset_key,
        "target": latest.target,
        "memory_context": memory,
        "items": [
            {
                "task_id": row.task_id,
                "status": row.status,
                "finding_count": row.finding_count,
                "risk_group_count": row.risk_group_count,
                "severity_counts": row.severity_counts or {},
                "risk_types": row.risk_types or [],
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ],
    }
