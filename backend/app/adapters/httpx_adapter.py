from __future__ import annotations

import json
import re
import time
import urllib.parse
from typing import Any

import httpx as http_client

from ..schemas.finding import Finding
from .base import BaseAdapter


class HttpxAdapter(BaseAdapter):
    name = "httpx"
    tool_version = "1.12.0"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        targets = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        targets = [str(item).strip() for item in targets if str(item).strip()]
        if not self.available() or not targets:
            return []
        completed = self._run(
            [
                "httpx",
                "-l",
                "-",
                "-silent",
                "-json",
                "-sc",
                "-title",
                "-td",
                "-rl",
                str(self._rate(options) * 10),
            ],
            "\n".join(targets) + "\n",
        )
        findings = self.parse_output(completed.stdout)
        seen = {item.url for item in findings if item.url}
        missing = [target for target in targets if target not in seen]
        findings.extend(self._http_fallback(missing, self._rate(options), options))
        return self._filter_findings(findings, options)

    def _http_fallback(
        self,
        targets: list[str],
        rate: int,
        options: dict[str, Any],
    ) -> list[Finding]:
        output: list[Finding] = []
        headers = {"User-Agent": "attack-surface-scanner/0.1"}
        with http_client.Client(
            timeout=None,
            follow_redirects=False,
            headers=headers,
        ) as client:
            for target in targets:
                if not self._candidate_allowed(target, options):
                    continue
                try:
                    response = client.get(target)
                except http_client.HTTPError:
                    continue
                blocked = False
                for _ in range(5):
                    if not response.is_redirect:
                        break
                    location = response.headers.get("location", "")
                    if not location:
                        break
                    next_url = urllib.parse.urljoin(str(response.url), location)
                    if not self._candidate_allowed(next_url, options):
                        blocked = True
                        break
                    try:
                        response = client.get(next_url)
                    except http_client.HTTPError:
                        blocked = True
                        break
                if blocked:
                    continue
                title_match = re.search(
                    r"<title[^>]*>(.*?)</title>",
                    response.text,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                parsed = urllib.parse.urlparse(str(response.url))
                output.append(
                    Finding(
                        source="httpx",
                        host=parsed.hostname or "",
                        url=str(response.url),
                        port=parsed.port,
                        vuln_type="live_endpoint",
                        severity="info",
                        evidence={
                            "status_code": response.status_code,
                            "title": title_match.group(1).strip() if title_match else "",
                            "tech": [],
                            "webserver": response.headers.get("server", ""),
                            "fallback": "python-httpx",
                        },
                        raw={"url": str(response.url), "final_url": str(response.url)},
                    )
                )
                time.sleep(1.0 / max(1, rate))
        return output

    @staticmethod
    def parse_output(text: str) -> list[Finding]:
        findings: list[Finding] = []
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = str(row.get("url") or row.get("input") or "")
            host = str(row.get("host") or "")
            port = row.get("port")
            findings.append(
                Finding(
                    source="httpx",
                    host=host,
                    url=url,
                    port=int(port) if port else None,
                    vuln_type="live_endpoint",
                    severity="info",
                    evidence={
                        "status_code": row.get("status_code"),
                        "title": row.get("title"),
                        "tech": row.get("tech"),
                        "webserver": row.get("webserver"),
                    },
                    raw=row,
                )
            )
        return findings
