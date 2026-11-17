from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.dedup import normalize_vuln_type
from app.config import settings


GROUPS = {
    "nuclei": {
        "sources": {"nuclei"},
        "tool_profile": "nuclei",
        "mode": "active",
    },
    "zap_wapiti_nuclei": {
        "sources": {"zap", "wapiti", "nuclei"},
        "tool_profile": "zap_wapiti_nuclei",
        "mode": "active",
    },
    "full_agent": {
        "sources": {
            "subfinder",
            "dnsx",
            "httpx",
            "nmap",
            "nuclei",
            "zap",
            "openvas",
            "schemathesis",
            "kubescape",
            "subjack",
            "gitleaks",
            "nikto",
            "wapiti",
        },
        "tool_profile": "full_agent",
        "mode": "full",
    },
}


def _token(api: str, username: str, password: str) -> str:
    response = httpx.post(
        f"{api}/api/auth/login",
        json={"username": username, "password": password},
        timeout=20,
    )
    response.raise_for_status()
    return str(response.json()["access_token"])


def _run_task(
    api: str,
    token: str,
    task: dict[str, Any],
    timeout: int,
) -> tuple[dict[str, Any], float]:
    headers = {"Authorization": f"Bearer {token}"}
    started = time.monotonic()
    created = httpx.post(
        f"{api}/api/tasks",
        headers=headers,
        json=task,
        timeout=30,
    )
    created.raise_for_status()
    task_id = created.json()["id"]
    deadline = started + timeout
    while time.monotonic() < deadline:
        response = httpx.get(
            f"{api}/api/tasks/{task_id}",
            headers=headers,
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        if payload["status"] in {
            "completed",
            "failed",
            "blocked",
            "cancelled",
        }:
            findings = httpx.get(
                f"{api}/api/tasks/{task_id}/findings",
                headers=headers,
                timeout=30,
            )
            findings.raise_for_status()
            payload["findings"] = findings.json().get("findings", [])
            return payload, time.monotonic() - started
        time.sleep(5)
    raise TimeoutError(f"task {task_id} exceeded {timeout}s")


def _matches(finding: dict[str, Any], categories: dict[str, list[str]]) -> str | None:
    text = (
        f"{finding.get('vuln_type', '')} "
        f"{finding.get('raw', {}).get('description', '')}"
    ).lower()
    for category, aliases in categories.items():
        if category.replace("_", " ") in text or category in text:
            return category
        if any(alias.lower() in text for alias in aliases):
            return category
    return None


def _metrics(
    findings: list[dict[str, Any]],
    categories: dict[str, list[str]],
) -> tuple[float, float, float, float]:
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
    recall = len(hit) / len(expected) if expected else 0.0
    precision = (
        max(0, security_findings - false_positive) / security_findings
        if security_findings
        else 0.0
    )
    false_positive_rate = (
        false_positive / security_findings if security_findings else 0.0
    )
    coverage = len(hit) / len(expected) if expected else 0.0
    return recall, precision, false_positive_rate, coverage


def main() -> int:
    parser = argparse.ArgumentParser(description="Run DVWA ablation experiments.")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    parser.add_argument(
        "--ground-truth",
        default=str(ROOT / "evaluation" / "ground_truth_dvwa.yaml"),
    )
    parser.add_argument("--results", default=str(ROOT / "evaluation" / "results.csv"))
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--task-timeout", type=int, default=3600)
    args = parser.parse_args()
    ground_truth = yaml.safe_load(Path(args.ground_truth).read_text(encoding="utf-8"))
    categories = dict(ground_truth.get("aliases") or {})
    for category in ground_truth.get("categories", []):
        categories.setdefault(category, [category.replace("_", " ")])
    categories = {
        normalize_vuln_type(category): aliases
        for category, aliases in categories.items()
    }
    token = _token(args.api, args.username, args.password)
    rows: list[dict[str, Any]] = []
    for group, group_config in GROUPS.items():
        sources = set(group_config["sources"])
        for repetition in range(1, args.repetitions + 1):
            task, elapsed = _run_task(
                args.api,
                token,
                {
                    "target": ground_truth["target"],
                    "auth_ref": "local-dvwa",
                    "max_rps": 5,
                    "mode": group_config["mode"],
                    "tool_profile": group_config["tool_profile"],
                },
                args.task_timeout,
            )
            filtered = [
                item
                for item in task.get("findings", [])
                if item.get("source") in sources
                or any(source in sources for source in item.get("also_reported_by", []))
            ]
            recall, precision, false_positive_rate, coverage = _metrics(
                filtered,
                categories,
            )
            row = {
                "group": group,
                "run": repetition,
                "findings": len(filtered),
                "recall": round(recall, 4),
                "precision": round(precision, 4),
                "false_positive_rate": round(false_positive_rate, 4),
                "elapsed_seconds": round(elapsed, 2),
                "coverage": round(coverage, 4),
                "task_id": task["id"],
                "status": task["status"],
            }
            rows.append(row)
            print(json.dumps(row, ensure_ascii=False))
    output = Path(args.results)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    doc = ROOT / "docs" / "evaluation.md"
    doc.parent.mkdir(parents=True, exist_ok=True)
    summary = [
        "# DVWA Ablation Evaluation",
        "",
        f"- Ground truth: `{args.ground_truth}`",
        f"- Repetitions per group: {args.repetitions}",
        f"- Raw results: `{args.results}`",
        "",
        "| Group | Runs | Mean Recall | Mean Precision | Mean FP Rate | Mean Seconds |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for group in GROUPS:
        selected = [row for row in rows if row["group"] == group]
        mean = lambda key: sum(row[key] for row in selected) / len(selected)
        summary.append(
            f"| {group} | {len(selected)} | {mean('recall'):.3f} | "
            f"{mean('precision'):.3f} | {mean('false_positive_rate'):.3f} | "
            f"{mean('elapsed_seconds'):.1f} |"
        )
    summary.extend(
        [
            "",
            "## Run Records",
            "",
            "| Group | Run | Findings | Seconds | Task ID |",
            "|---|---:|---:|---:|---|",
        ]
    )
    for row in rows:
        summary.append(
            f"| {row['group']} | {row['run']} | {row['findings']} | "
            f"{row['elapsed_seconds']} | `{row['task_id']}` |"
        )
    summary.extend(
        [
            "",
            "## Coverage Notes",
            "",
            "- Nuclei only reports matches from the pinned template set.",
            "- ZAP focuses on web configuration and active HTTP checks.",
            "- Wapiti contributes parameter-level SQLi, XSS, file, upload and CSRF checks.",
            "- Nmap contributes exposed services but is treated as informational unless correlated.",
            "- DVWA categories that no enabled engine checks are reported as coverage gaps rather than hidden.",
            "- XSS subcategories normalize to one `cross_site_scripting` category, yielding 12 unique ground-truth categories.",
            "- Precision and FP rate use strict ground-truth matching. Real security findings outside that fixed list count as unmatched, so these values are conservative.",
            f"- The experiment uses ZAP_MAX_SCAN_MINUTES={settings.zap_max_scan_minutes}.",
        ]
    )
    doc.write_text("\n".join(summary) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
