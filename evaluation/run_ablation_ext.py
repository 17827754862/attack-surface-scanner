# -*- coding: utf-8 -*-
"""3×3 消融实验（扩展版）：在原指标基础上补充风险组、计分分母与命中类别明细。

不改动原始证据 results.csv，输出到独立文件。
用法：
    python evaluation/run_ablation_ext.py --password xxx --results evaluation/results-2026-11-15.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.dedup import normalize_vuln_type  # noqa: E402
from run_ablation import GROUPS, _matches, _run_task, _token  # noqa: E402


def compute(findings: list[dict[str, Any]], categories: dict[str, list[str]]) -> dict[str, Any]:
    expected = set(categories)
    hit: set[str] = set()
    false_positive = 0
    security_findings = 0
    for finding in findings:
        if finding.get("severity") == "info":
            continue
        security_findings += 1
        match = _matches(finding, categories)
        if match:
            hit.add(match)
        else:
            false_positive += 1
    matched_findings = security_findings - false_positive
    return {
        "security_findings": security_findings,
        "matched_findings": matched_findings,
        "category_hits": len(hit),
        "recall": len(hit) / len(expected) if expected else 0.0,
        "precision": matched_findings / security_findings if security_findings else None,
        "fp_rate": false_positive / security_findings if security_findings else None,
        "coverage": len(hit) / len(expected) if expected else 0.0,
        "hit_categories": ",".join(sorted(hit)),
    }


def task_detail(api: str, token: str, task_id: str) -> dict[str, Any]:
    response = httpx.get(
        f"{api}/api/tasks/{task_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--ground-truth", default=str(ROOT / "evaluation" / "ground_truth_dvwa.yaml"))
    parser.add_argument("--results", default=str(ROOT / "evaluation" / "results-ext.csv"))
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--task-timeout", type=int, default=1800)
    parser.add_argument("--only", default="", help="只跑指定组，逗号分隔")
    parser.add_argument("--append", action="store_true", help="追加到已有结果文件")
    args = parser.parse_args()

    ground_truth = yaml.safe_load(Path(args.ground_truth).read_text(encoding="utf-8"))
    categories = dict(ground_truth.get("aliases") or {})
    for category in ground_truth.get("categories", []):
        categories.setdefault(category, [category.replace("_", " ")])
    categories = {normalize_vuln_type(k): v for k, v in categories.items()}
    print(f"[init] ground truth 类别数 = {len(categories)}", flush=True)

    token = _token(args.api, args.username, args.password)
    rows: list[dict[str, Any]] = []
    out = Path(args.results)
    if args.append and out.exists():
        with out.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        print(f"[append] 已有 {len(rows)} 行", flush=True)

    wanted = {x.strip() for x in args.only.split(",") if x.strip()}
    for group, cfg in GROUPS.items():
        if wanted and group not in wanted:
            continue
        sources = set(cfg["sources"])
        done = [int(r["run"]) for r in rows if r["group"] == group]
        start = max(done) if done else 0
        for rep in range(start + 1, start + args.repetitions + 1):
            print(f"[run] {group} #{rep} start", flush=True)
            task, elapsed = _run_task(
                args.api,
                token,
                {
                    "target": ground_truth["target"],
                    "auth_ref": "local-dvwa",
                    "max_rps": 5,
                    "mode": cfg["mode"],
                    "tool_profile": cfg["tool_profile"],
                    "authorization_confirmed": True,
                    "validation_level": "safe",
                    "oast_enabled": False,
                },
                args.task_timeout,
            )
            filtered = [
                item
                for item in task.get("findings", [])
                if item.get("source") in sources
                or any(s in sources for s in item.get("also_reported_by", []))
            ]
            stats = compute(filtered, categories)
            detail = task_detail(args.api, token, task["id"])
            risk_groups = detail.get("risk_groups") or []

            row = {
                "group": group,
                "run": rep,
                "findings": len(filtered),
                "security_findings": stats["security_findings"],
                "matched_findings": stats["matched_findings"],
                "risk_groups": len(risk_groups),
                "category_hits": stats["category_hits"],
                "recall": round(stats["recall"], 4),
                "precision": None if stats["precision"] is None else round(stats["precision"], 4),
                "fp_rate": None if stats["fp_rate"] is None else round(stats["fp_rate"], 4),
                "coverage": round(stats["coverage"], 4),
                "elapsed_seconds": round(elapsed, 2),
                "task_id": task["id"],
                "status": task["status"],
                "hit_categories": stats["hit_categories"],
            }
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)

            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)

    print("[done] rows =", len(rows), "->", args.results, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
