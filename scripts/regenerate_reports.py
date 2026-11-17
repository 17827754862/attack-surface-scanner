from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from app.db import SessionLocal, Task
from app.report import render_report
from app.schemas.finding import Finding


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild stored HTML and JSON reports with the current report template."
    )
    parser.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR", "/output"))
    parser.add_argument("--task-id", default="")
    args = parser.parse_args()

    root = Path(args.output_dir)
    paths = (
        [root / args.task_id / "report.json"]
        if args.task_id
        else sorted(root.glob("*/report.json"))
    )
    rebuilt = 0
    skipped = 0
    for path in paths:
        if not path.is_file():
            skipped += 1
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            task_id = str(payload.get("task_id") or path.parent.name)
            findings = [
                Finding.model_validate(item)
                for item in payload.get("findings") or []
            ]
            result = render_report(
                task_id=task_id,
                target=str(payload.get("target") or ""),
                status=str(payload.get("status") or "completed"),
                findings=findings,
                node_status=dict(payload.get("node_status") or {}),
                trace=list(payload.get("execution_trace") or []),
                output_dir=str(root),
                llm_summary=dict(payload.get("llm_summary") or {}),
                blocked_targets=list(payload.get("blocked_targets") or []),
                risk_groups=list(payload.get("risk_groups") or []),
                memory_context=dict(payload.get("memory_context") or {}),
                budget_context=dict(payload.get("budget_context") or {}),
            )
            rebuilt_payload = json.loads(
                Path(result["json"]).read_text(encoding="utf-8")
            )
            db = SessionLocal()
            try:
                task = db.get(Task, task_id)
                if task is not None:
                    task.report_html = result["html"]
                    task.report_json = rebuilt_payload
                    task.workflow_png = result["png"]
                    task.workflow_mmd = result["mermaid"]
                    db.commit()
            finally:
                db.close()
        except Exception as exc:
            skipped += 1
            print(f"skip {path.parent.name}: {exc}")
            continue
        rebuilt += 1
        print(f"rebuilt {task_id}")

    print(f"rebuilt={rebuilt} skipped={skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
