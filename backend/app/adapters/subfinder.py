from __future__ import annotations

import json
from typing import Any

from ..schemas.finding import Finding
from .base import BaseAdapter


class SubfinderAdapter(BaseAdapter):
    name = "subfinder"
    tool_version = "2.17.0"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        domain = str(target_or_input).strip()
        if not self.available() or not domain:
            return []
        completed = self._run(
            [
                "subfinder",
                "-d",
                domain,
                "-silent",
                "-json",
                "-rl",
                str(self._rate(options) * 10),
            ]
        )
        return self._filter_findings(
            self.parse_output(completed.stdout, domain),
            options,
        )

    @staticmethod
    def parse_output(text: str, domain: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                host = str(row.get("host") or row.get("input") or "").strip()
            except json.JSONDecodeError:
                host = line
            if not host:
                continue
            findings.append(
                Finding(
                    source="subfinder",
                    host=host,
                    vuln_type="subdomain",
                    severity="info",
                    evidence={"domain": domain, "subdomain": host},
                    raw={"subdomain": host},
                )
            )
        return findings
