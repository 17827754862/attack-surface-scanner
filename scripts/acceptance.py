from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

import httpx


def wait_health(api: str, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = httpx.get(f"{api}/health", timeout=3)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(3)
    raise TimeoutError("API health check timed out")


def login(api: str, username: str, password: str) -> dict[str, str]:
    response = httpx.post(
        f"{api}/api/auth/login",
        json={"username": username, "password": password},
        timeout=20,
    )
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def submit(
    api: str,
    headers: dict[str, str],
    target: str,
    auth_ref: str,
    **overrides,
) -> str:
    payload = {
        "target": target,
        "auth_ref": auth_ref,
        "authorization_confirmed": True,
        "max_rps": 5,
        "mode": "active",
    }
    payload.update(overrides)
    response = httpx.post(
        f"{api}/api/tasks",
        headers=headers,
        json=payload,
        timeout=30,
    )
    response.raise_for_status()
    return str(response.json()["id"])


def wait_task(
    api: str,
    headers: dict[str, str],
    task_id: str,
    timeout: int = 3600,
) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        response = httpx.get(
            f"{api}/api/tasks/{task_id}",
            headers=headers,
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        if payload["status"] in {
            "completed",
            "partial",
            "failed",
            "blocked",
            "cancelled",
        }:
            return payload
        time.sleep(5)
    raise TimeoutError(f"task {task_id} timed out")


def validate_report(
    api: str,
    headers: dict[str, str],
    task_id: str,
    output: Path,
) -> None:
    report = httpx.get(
        f"{api}/api/tasks/{task_id}/report",
        headers=headers,
        timeout=30,
    )
    report.raise_for_status()
    (output / "report.html").write_text(report.text, encoding="utf-8")
    report_json = httpx.get(
        f"{api}/api/tasks/{task_id}/report",
        params={"format": "json"},
        headers=headers,
        timeout=30,
    )
    report_json.raise_for_status()
    payload = report_json.json()
    (output / "findings.json").write_text(
        json.dumps(payload.get("findings", []), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    png = httpx.get(
        f"{api}/api/tasks/{task_id}/workflow.png",
        headers=headers,
        timeout=30,
    )
    if png.status_code == 200:
        (output / "workflow.png").write_bytes(png.content)
    else:
        mmd = httpx.get(
            f"{api}/api/tasks/{task_id}/graph.mmd",
            headers=headers,
            timeout=30,
        )
        mmd.raise_for_status()
        (output / "workflow.mmd").write_text(mmd.text, encoding="utf-8")


def validate_evidence(
    api: str,
    headers: dict[str, str],
    task_id: str,
) -> None:
    findings = httpx.get(
        f"{api}/api/tasks/{task_id}/findings",
        headers=headers,
        timeout=20,
    )
    findings.raise_for_status()
    rows = findings.json().get("findings", [])
    if not rows:
        raise AssertionError("DVWA task produced no findings")
    fingerprint = rows[0]["fingerprint"]
    response = httpx.get(
        f"{api}/api/tasks/{task_id}/evidence/{fingerprint}",
        headers=headers,
        timeout=20,
    )
    response.raise_for_status()
    evidence_hash = response.headers.get("x-evidence-sha256", "")
    if not evidence_hash or evidence_hash != rows[0]["evidence_hash"]:
        raise AssertionError("evidence hash verification failed")


def validate_cancel_resume(
    api: str,
    headers: dict[str, str],
) -> str:
    task_id = submit(api, headers, "http://mock:8000", "local-mock")
    deadline = time.time() + 60
    while time.time() < deadline:
        current = httpx.get(
            f"{api}/api/tasks/{task_id}",
            headers=headers,
            timeout=20,
        )
        current.raise_for_status()
        payload = current.json()
        if any(value in {"done", "running"} for value in payload["node_status"].values()):
            break
        time.sleep(2)
    canceled = httpx.post(
        f"{api}/api/tasks/{task_id}/cancel",
        headers=headers,
        timeout=20,
    )
    canceled.raise_for_status()
    if canceled.json()["status"] != "cancelled":
        raise AssertionError("cancel did not set cancelled status")
    resumed = httpx.post(
        f"{api}/api/tasks/{task_id}/resume",
        headers=headers,
        timeout=20,
    )
    resumed.raise_for_status()
    deadline = time.time() + 3600
    final = resumed.json()
    while time.time() < deadline:
        current = httpx.get(
            f"{api}/api/tasks/{task_id}",
            headers=headers,
            timeout=20,
        )
        current.raise_for_status()
        final = current.json()
        if final["status"] in {"completed", "failed"}:
            break
        time.sleep(5)
    else:
        raise TimeoutError(f"resume for {task_id} timed out")
    if final["status"] not in {"completed", "failed"}:
        raise AssertionError(f"resume ended with {final['status']}")
    failed_nodes = [
        name
        for name, status in final["node_status"].items()
        if status == "failed"
    ]
    if failed_nodes:
        raise AssertionError(f"resume retained failed nodes: {failed_nodes}")
    if final.get("findings_count", 0) < 1:
        raise AssertionError("resume completed without producing findings")
    return task_id


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="changeme")
    parser.add_argument("--output", default="acceptance-results")
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    wait_health(args.api)
    headers = login(args.api, args.username, args.password)

    unauthorized = httpx.post(
        f"{args.api}/api/tasks",
        headers=headers,
        json={
            "target": "http://dvwa",
            "auth_ref": "none",
            "max_rps": 5,
            "mode": "active",
        },
        timeout=20,
    )
    if unauthorized.status_code != 403:
        raise AssertionError("authorization confirmation gate did not return 403")

    mock_id = submit(args.api, headers, "http://mock:8000", "local-mock")
    mock = wait_task(args.api, headers, mock_id)
    if mock["node_status"].get("api_fuzz") != "done":
        raise AssertionError("mock OpenAPI branch did not execute")
    if mock["node_status"].get("k8s_audit") != "skipped":
        raise AssertionError("mock k8s fallback did not skip")

    dvwa_id = submit(args.api, headers, "http://dvwa", "local-dvwa")
    dvwa = wait_task(args.api, headers, dvwa_id)
    if dvwa["status"] != "completed":
        raise AssertionError(f"DVWA task status is {dvwa['status']}")
    if dvwa["node_status"].get("web_scan") != "done":
        raise AssertionError("ZAP did not complete")
    validate_report(args.api, headers, dvwa_id, output)
    validate_evidence(args.api, headers, dvwa_id)
    subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "worker",
            "sh",
            "-c",
            (
                f"test -s /output/{dvwa_id}/findings.json "
                f"&& test -s /output/{dvwa_id}/report.html "
                f"&& test -s /output/{dvwa_id}/workflow.png"
            ),
        ],
        check=True,
    )
    dvwa_findings = httpx.get(
        f"{args.api}/api/tasks/{dvwa_id}/findings",
        headers=headers,
        timeout=20,
    )
    dvwa_findings.raise_for_status()

    validation_id = submit(
        args.api,
        headers,
        "http://dvwa",
        "local-dvwa",
        mode="active",
        tool_profile="validation_only",
        time_profile="quick",
        time_budget_seconds=300,
        validation_level="deep",
        oast_enabled=True,
    )
    validation = wait_task(args.api, headers, validation_id)
    if validation["status"] not in {"completed", "partial"}:
        raise AssertionError(f"validation-only task status is {validation['status']}")
    if validation["node_status"].get("active_validation") not in {"done", "skipped"}:
        raise AssertionError("active_validation did not reach a terminal state")
    if validation["node_status"].get("credential_session_analysis") not in {
        "done",
        "skipped",
    }:
        raise AssertionError("credential_session_analysis did not reach a terminal state")

    subprocess.run(
        [
            "python",
            "scripts/verify_dvwa_auth.py",
            "--output",
            str(output / "dvwa-auth.json"),
        ],
        check=True,
    )
    subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "worker",
            "python",
            "/app/scripts/verify_zap_auth.py",
            "--output",
            f"/output/{dvwa_id}/zap-auth.json",
        ],
        check=True,
    )
    cancel_task_id = validate_cancel_resume(args.api, headers)
    result = {
        "mock_task": mock_id,
        "dvwa_task": dvwa_id,
        "cancel_resume_task": cancel_task_id,
        "validation_task": validation_id,
        "findings": dvwa_findings.json().get("count", 0),
        "status": "passed",
    }
    (output / "acceptance.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
