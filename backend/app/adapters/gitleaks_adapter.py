from __future__ import annotations

import json
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

import httpx

from ..schemas.finding import Finding
from .base import BaseAdapter


class GitleaksAdapter(BaseAdapter):
    name = "gitleaks"
    tool_version = "8.30.1"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        urls = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        urls = [str(item) for item in urls if str(item).lower().split("?", 1)[0].endswith(".js")]
        if not self.available() or not urls:
            return []
        with tempfile.TemporaryDirectory(prefix="gitleaks_") as temp_dir:
            root = Path(temp_dir)
            file_urls: dict[str, str] = {}
            for index, url in enumerate(urls[:20]):
                if not self._candidate_allowed(url, options):
                    continue
                try:
                    response = httpx.get(
                        url,
                        timeout=None,
                        follow_redirects=False,
                        headers={"User-Agent": "attack-surface-scanner/0.1"},
                    )
                    blocked = False
                    for _ in range(5):
                        if not response.is_redirect:
                            break
                        next_url = urllib.parse.urljoin(
                            str(response.url),
                            response.headers.get("location", ""),
                        )
                        if not self._candidate_allowed(next_url, options):
                            blocked = True
                            break
                        response = httpx.get(
                            next_url,
                            timeout=None,
                            follow_redirects=False,
                            headers={"User-Agent": "attack-surface-scanner/0.1"},
                        )
                    if blocked:
                        continue
                    filename = f"script-{index}.js"
                    (root / filename).write_text(
                        response.text,
                        encoding="utf-8",
                        errors="replace",
                    )
                    file_urls[filename] = url
                except Exception:
                    continue
            completed = self._run(
                [
                    "gitleaks",
                    "detect",
                    "--no-git",
                    "--source",
                    str(root),
                    "--report-format",
                    "json",
                    "--report-path",
                    "-",
                ]
            )
            return self._filter_findings(
                self.parse_output(completed.stdout, file_urls),
                options,
            )

    @staticmethod
    def parse_output(
        text: str,
        file_urls: dict[str, str] | None = None,
    ) -> list[Finding]:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for item in payload if isinstance(payload, list) else []:
            source_file = Path(str(item.get("File", ""))).name
            source_url = (file_urls or {}).get(source_file, str(item.get("File") or ""))
            findings.append(
                Finding(
                    source="gitleaks",
                    host=urllib.parse.urlparse(source_url).hostname or "",
                    url=source_url,
                    vuln_type=f"secret:{item.get('RuleID', 'unknown')}",
                    severity="high",
                    evidence={
                        "description": item.get("Description"),
                        "match": item.get("Match"),
                        "file": source_file,
                    },
                    raw=item,
                )
            )
        return findings
