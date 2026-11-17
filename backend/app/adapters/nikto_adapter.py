from __future__ import annotations

import json
from typing import Any

from ..schemas.finding import Finding
from .base import BaseAdapter


class NiktoAdapter(BaseAdapter):
    name = "nikto"
    tool_version = "2.6.1"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        urls = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        if not self.available():
            return []
        findings: list[Finding] = []
        for url in [str(item) for item in urls if str(item)]:
            completed = self._run(
                ["nikto", "-host", url, "-Format", "json", "-output", "-", "-nointeractive"]
            )
            findings.extend(self.parse_output(completed.stdout, url))
        return self._filter_findings(findings, options)

    @staticmethod
    def parse_output(text: str, url: str) -> list[Finding]:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return []
        rows = payload if isinstance(payload, list) else payload.get("vulnerabilities", [])
        output: list[Finding] = []
        for item in rows if isinstance(rows, list) else []:
            output.append(
                Finding(
                    source="nikto",
                    host="",
                    url=url,
                    vuln_type=str(item.get("msg") or item.get("id") or "nikto finding"),
                    severity="medium",
                    evidence=item,
                    raw=item,
                )
            )
        return output
