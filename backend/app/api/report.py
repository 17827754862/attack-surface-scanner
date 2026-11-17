from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session

from ..db import Task, get_db
from ..evidence import EvidenceStore
from ..config import settings
from ..security import get_current_user
from ..workflow_image import render_workflow


router = APIRouter(prefix="/api/tasks", tags=["report"])


def _task(task_id: str, db: Session) -> Task:
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    return task


@router.get("/{task_id}/report")
def get_report(
    task_id: str,
    format: str = "html",
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    task = _task(task_id, db)
    if format == "json":
        return task.report_json or {}
    if task.report_html and Path(task.report_html).exists():
        return HTMLResponse(Path(task.report_html).read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="report not generated")


@router.get("/{task_id}/workflow.png")
def get_workflow_png(
    task_id: str,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    task = _task(task_id, db)
    if not task.workflow_png or not Path(task.workflow_png).exists():
        raise HTTPException(status_code=404, detail="workflow png not found")
    return FileResponse(task.workflow_png, media_type="image/png")


@router.post("/{task_id}/workflow/regenerate")
def regenerate_workflow_image(
    task_id: str,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    task = _task(task_id, db)
    report_data = task.report_json or {}
    resume_state = task.resume_state or {}
    trace = report_data.get("execution_trace") or resume_state.get("execution_trace") or []
    node_status = report_data.get("node_status") or task.node_status or {}
    result = render_workflow(
        task_id=task.id,
        trace=list(trace),
        node_status=dict(node_status),
        output_dir=settings.output_dir,
    )
    task.workflow_mmd = str(result.get("mermaid") or "")
    task.workflow_png = str(result.get("png") or "")
    if task.report_json:
        current = dict(task.report_json)
        current["workflow"] = {
            "mermaid": task.workflow_mmd,
            "png": task.workflow_png or None,
        }
        task.report_json = current
    db.commit()
    if not task.workflow_png or not Path(task.workflow_png).exists():
        raise HTTPException(
            status_code=503,
            detail="workflow image renderer is unavailable; Mermaid source is still available",
        )
    return FileResponse(
        task.workflow_png,
        media_type="image/png",
        headers={"Cache-Control": "no-store"},
    )


@router.get("/{task_id}/graph.mmd")
def get_graph_mmd(
    task_id: str,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    task = _task(task_id, db)
    if not task.workflow_mmd or not Path(task.workflow_mmd).exists():
        raise HTTPException(status_code=404, detail="mermaid graph not found")
    return PlainTextResponse(Path(task.workflow_mmd).read_text(encoding="utf-8"))


@router.get("/{task_id}/evidence/{fingerprint}")
def get_evidence(
    task_id: str,
    fingerprint: str,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    _task(task_id, db)
    store = EvidenceStore(settings.output_dir, task_id)
    evidence_hash = store.find_by_fingerprint(fingerprint)
    if not evidence_hash:
        raise HTTPException(status_code=404, detail="evidence not found")
    try:
        store.read_verified(evidence_hash)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=409, detail="evidence verification failed") from exc
    path = store.root / f"{evidence_hash}.json"
    return FileResponse(
        path,
        media_type="application/json",
        filename=f"{fingerprint}.json",
        headers={"X-Evidence-SHA256": evidence_hash},
    )
