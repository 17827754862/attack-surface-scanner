from __future__ import annotations

import json
import os
from typing import Any

from ..config import settings
from ..schemas.finding import Finding
from .base import BaseAdapter


SEVERITY = {"info", "low", "medium", "high", "critical"}


class NucleiAdapter(BaseAdapter):
    name = "nuclei"
    tool_version = "3.11.1"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        targets = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        targets = list(
            dict.fromkeys(
                str(item).strip()
                for item in targets
                if str(item).strip()
            )
        )[: max(1, settings.nuclei_max_targets)]
        if not self.available() or not targets:
            return []
        command = [
            "nuclei",
            "-l",
            "-",
            "-t",
            os.getenv("NUCLEI_TEMPLATES", "/opt/nuclei-templates"),
            "-jsonl",
            "-silent",
            "-severity",
            options.get("severity") or settings.nuclei_severity,
            "-rate-limit",
            str(self._rate(options)),
            "-duc",
            "-ni",
        ]
        tags = options.get("tags") or [
            item.strip()
            for item in settings.nuclei_tags.split(",")
            if item.strip()
        ]
        if tags:
            command.extend(["-tags", ",".join(str(tag) for tag in tags)])
        completed = self._run(command, "\n".join(targets) + "\n")
        findings = self.parse_output(completed.stdout)
        return self._filter_findings(findings, options)

    @staticmethod
    def parse_output(text: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = row.get("info") or {}
            severity = str(info.get("severity") or "info").lower()
            if severity not in SEVERITY:
                severity = "info"
            matched = str(row.get("matched-at") or row.get("host") or "")
            findings.append(
                Finding(
                    source="nuclei",
                    host=str(row.get("host") or ""),
                    url=matched or None,
                    port=int(row["port"]) if str(row.get("port", "")).isdigit() else None,
                    vuln_type=str(info.get("name") or row.get("template-id") or "nuclei"),
                    severity=severity,  # type: ignore[arg-type]
                    evidence={
                        "template_id": row.get("template-id"),
                        "matched_at": matched,
                        "description": info.get("description"),
                    },
                    raw=row,
                )
            )
        return findings
