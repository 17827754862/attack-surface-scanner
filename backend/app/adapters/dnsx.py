from __future__ import annotations

import re
from typing import Any

from ..schemas.finding import Finding
from .base import BaseAdapter


class DnsxAdapter(BaseAdapter):
    name = "dnsx"
    tool_version = "1.3.1"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        hosts = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        hosts = [str(item).strip() for item in hosts if str(item).strip()]
        if not self.available() or not hosts:
            return []
        completed = self._run(
            ["dnsx", "-silent", "-a", "-resp", "-rl", str(self._rate(options) * 10)],
            "\n".join(hosts) + "\n",
        )
        return self._filter_findings(self.parse_output(completed.stdout), options)

    @staticmethod
    def parse_output(text: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            match = re.match(r"^(\S+)\s+\[([^\]]+)\]", line)
            host = match.group(1) if match else line.split()[0]
            address = match.group(2) if match else ""
            findings.append(
                Finding(
                    source="dnsx",
                    host=host,
                    vuln_type="resolved_host",
                    severity="info",
                    evidence={"address": address, "line": line},
                    raw={"line": line},
                )
            )
        return findings
