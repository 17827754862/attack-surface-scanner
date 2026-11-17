from __future__ import annotations

import json
import os
from typing import Any

from ..schemas.finding import Finding
from .base import BaseAdapter


class KubescapeAdapter(BaseAdapter):
    name = "kubescape"
    tool_version = "4.0.16"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        if not self.available() or not os.getenv("KUBECONFIG"):
            return []
        completed = self._run(
            ["kubescape", "scan", "framework", "nsa", "--format", "json", "--output", "-"]
        )
        if completed.returncode not in (0, 1):
            return []
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return []
        return self._filter_findings(
            self.parse_output(payload, str(target_or_input)),
            options,
        )

    @staticmethod
    def parse_output(payload: dict[str, Any], target: str) -> list[Finding]:
        output: list[Finding] = []
        controls = payload.get("summaryDetails", {}).get("controls", {})
        if isinstance(controls, dict):
            iterator = controls.items()
        else:
            iterator = []
        for control_id, value in iterator:
            status = str(value.get("status") or "").lower()
            if status in {"passed", "skipped"}:
                continue
            output.append(
                Finding(
                    source="kubescape",
                    host=target,
                    vuln_type=f"k8s_control:{control_id}",
                    severity="medium",
                    evidence={"status": status, "name": value.get("name")},
                    raw=value if isinstance(value, dict) else {"value": value},
                )
            )
        return output
