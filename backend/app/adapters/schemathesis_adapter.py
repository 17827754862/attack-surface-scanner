from __future__ import annotations

from typing import Any

from ..schemas.finding import Finding
from .base import BaseAdapter


class SchemathesisAdapter(BaseAdapter):
    name = "schemathesis"
    tool_version = "3.38.5"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        urls = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        if not self.available():
            return []
        output: list[Finding] = []
        for url in [str(item) for item in urls if str(item)]:
            completed = self._run(
                [
                    "schemathesis",
                    "run",
                    url,
                    "--checks",
                    "all",
                ]
            )
            if completed.returncode != 0:
                output.append(
                    self._finding(
                        host=url,
                        url=url,
                        vuln_type="api_contract_failure",
                        severity="medium",
                        evidence={
                            "returncode": completed.returncode,
                            "stdout": completed.stdout[-2000:],
                            "stderr": completed.stderr[-1000:],
                        },
                        raw={"command": "schemathesis"},
                    )
                )
        return self._filter_findings(output, options)
