from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import Task, get_db
from ..security import get_current_user


router = APIRouter(prefix="/api/tasks", tags=["findings"])


@router.get("/{task_id}/findings")
def list_findings(
    task_id: str,
    severity: str | None = None,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
) -> dict:
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    findings = task.findings or []
    if severity:
        findings = [item for item in findings if item.get("severity") == severity]
    return {"count": len(findings), "findings": findings}
