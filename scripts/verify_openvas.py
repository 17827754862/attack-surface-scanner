from __future__ import annotations

import argparse
import json
import time

import httpx


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate OpenVAS integration or report degradation.")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    args = parser.parse_args()
    login = httpx.post(
        f"{args.api}/api/auth/login",
        json={"username": args.username, "password": args.password},
        timeout=20,
    )
    login.raise_for_status()
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    openvas: dict = {}
    deadline = time.time() + 180
    while time.time() < deadline:
        capabilities = httpx.get(
            f"{args.api}/api/capabilities",
            headers=headers,
            timeout=20,
        )
        capabilities.raise_for_status()
        openvas = capabilities.json().get("openvas", {})
        if openvas.get("available") or openvas.get("error") not in {
            None,
            "tool_not_installed",
            "service_unreachable",
            "gvm_cli_not_installed",
        }:
            break
        time.sleep(5)
    task = httpx.post(
        f"{args.api}/api/tasks",
        headers=headers,
        json={
            "target": "http://dvwa",
            "auth_ref": "local-dvwa",
            "authorization_confirmed": True,
            "max_rps": 5,
            "mode": "full",
        },
        timeout=30,
    )
    task.raise_for_status()
    task_id = task.json()["id"]
    deadline = time.time() + 3700
    while time.time() < deadline:
        payload = httpx.get(
            f"{args.api}/api/tasks/{task_id}",
            headers=headers,
            timeout=20,
        ).json()
        if payload["node_status"].get("host_vuln_scan") in {
            "done",
            "failed",
            "skipped",
        }:
            print(json.dumps({
                "status": (
                    "validated"
                    if payload["node_status"]["host_vuln_scan"] == "done"
                    else "degraded"
                ),
                "task_id": task_id,
                "host_vuln_scan": payload["node_status"]["host_vuln_scan"],
                "errors": payload["errors"],
                "capabilities": openvas,
            }, ensure_ascii=False, indent=2))
            return 0
        time.sleep(10)
    raise TimeoutError("OpenVAS validation task timed out")


if __name__ == "__main__":
    raise SystemExit(main())
