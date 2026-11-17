from __future__ import annotations

from typing import Any

from ..schemas.finding import Finding
from .base import BaseAdapter


class SubjackAdapter(BaseAdapter):
    name = "subjack"
    tool_version = "3.1.0"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        hosts = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        hosts = [str(item).strip() for item in hosts if str(item).strip()]
        if not self.available() or not hosts:
            return []
        completed = self._run(
            [
                "subjack",
                "-w",
                "-",
                "-t",
                str(self._rate(options)),
                "-ssl",
                "-c",
                "/opt/subjack/fingerprints.json",
                "-v",
            ],
            "\n".join(hosts) + "\n",
        )
        return self._filter_findings(self.parse_output(completed.stdout), options)

    @staticmethod
    def parse_output(text: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in text.splitlines():
            if "vulnerable" not in line.lower() and "[vulnerable]" not in line.lower():
                continue
            host = line.split()[0] if line.split() else ""
            findings.append(
                Finding(
                    source="subjack",
                    host=host,
                    vuln_type="subdomain_takeover",
                    severity="high",
                    evidence={"line": line.strip()},
                    raw={"line": line.strip()},
                )
            )
        return findings
