from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import AuditLog, User, get_db
from ..security import get_current_user


router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def list_audit_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    rows = (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    return {
        "count": len(rows),
        "items": [
            {
                "username": item.username,
                "action": item.action,
                "target": item.target,
                "task_id": item.task_id,
                "detail": item.detail,
                "created_at": item.created_at.isoformat(),
            }
            for item in rows
        ],
    }
