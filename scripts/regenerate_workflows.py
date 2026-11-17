from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from app.workflow_image import render_workflow


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Regenerate workflow PNG and Mermaid files from stored reports."
    )
    parser.add_argument(
        "--output-dir",
        default=os.getenv("OUTPUT_DIR", "/output"),
        help="Directory containing one task folder per report.",
    )
    parser.add_argument(
        "--task-id",
        default="",
        help="Only regenerate one task ID.",
    )
    args = parser.parse_args()

    root = Path(args.output_dir)
    reports = (
        [root / args.task_id / "report.json"]
        if args.task_id
        else sorted(root.glob("*/report.json"))
    )
    regenerated = 0
    skipped = 0
    for report_path in reports:
        if not report_path.is_file():
            skipped += 1
            continue
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            task_id = str(payload.get("task_id") or report_path.parent.name)
            result = render_workflow(
                task_id=task_id,
                trace=list(payload.get("execution_trace") or []),
                node_status=dict(payload.get("node_status") or {}),
                output_dir=str(root),
            )
        except Exception as exc:
            skipped += 1
            print(f"skip {report_path.parent.name}: {exc}")
            continue
        regenerated += 1
        print(f"updated {task_id}: {result['png'] or result['mermaid']}")

    print(f"regenerated={regenerated} skipped={skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
