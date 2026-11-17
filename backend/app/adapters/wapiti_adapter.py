from __future__ import annotations

import json
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from ..schemas.finding import Finding
from ..auth_session import authenticate
from .base import BaseAdapter


LEVEL = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


class WapitiAdapter(BaseAdapter):
    name = "wapiti"
    tool_version = "3.3.2"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        urls = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        if not self.available():
            return []
        findings: list[Finding] = []
        auth_cookie = ""
        if options.get("auth_scan"):
            auth_cookie, authenticated = self._login_cookie(
                str(options.get("auth_ref") or "")
            )
            options.setdefault("auth_metrics", {})["wapiti_authenticated"] = authenticated
            if not authenticated:
                raise RuntimeError("authentication_failed")
        for url in [str(item) for item in urls if str(item)]:
            with tempfile.TemporaryDirectory(prefix="wapiti_") as temp_dir:
                report_path = Path(temp_dir) / "report.json"
                command = [
                    "wapiti",
                    "-u",
                    url,
                    "-f",
                    "json",
                    "-o",
                    str(report_path),
                    "--flush-session",
                    "--scope",
                    "page",
                    "-l",
                    "2",
                    "-m",
                    "sql,timesql,xss,file,upload,redirect,exec,permanentxss,"
                    "http_headers,csp,brute_login_form,backup,ssrf,xxe,crlf,"
                    "methods,shellshock,spring4shell,log4shell,ssl",
                    "--max-links-per-page",
                    "50",
                    "--max-parameters",
                    "100",
                    "--wait",
                    str(max(1, int(1 / self._rate(options)))),
                ]
                excluded_paths = list(
                    dict.fromkeys(
                        [
                            *options.get("safe_path_denylist", []),
                            *options.get("active_scan_exclude", []),
                        ]
                    )
                )
                for excluded in excluded_paths:
                    value = str(excluded).strip()
                    if not value:
                        continue
                    command.extend(
                        [
                            "-x",
                            value
                            if "://" in value
                            else urllib.parse.urljoin(url, f"/{value.lstrip('/')}"),
                        ]
                    )
                if auth_cookie:
                    command.extend(["-C", auth_cookie])
                self._run(command)
                if report_path.exists():
                    findings.extend(
                        self.parse_output(report_path.read_text(encoding="utf-8"), url)
                    )
        return self._filter_findings(findings, options)

    @staticmethod
    def _login_cookie(auth_ref: str) -> tuple[str, bool]:
        result = authenticate(auth_ref)
        return result.cookie_header, result.authenticated

    @staticmethod
    def parse_output(text: str, url: str) -> list[Finding]:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return []
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else {}
        output: list[Finding] = []
        for category, entries in (vulnerabilities or {}).items():
            for entry in entries if isinstance(entries, list) else []:
                level = int(entry.get("level") or 0)
                path = entry.get("path")
                if isinstance(path, list):
                    path = next((item for item in path if item), "")
                finding_url = urllib.parse.urljoin(url, str(path or ""))
                parsed = urllib.parse.urlparse(finding_url)
                output.append(
                    Finding(
                        source="wapiti",
                        host=parsed.hostname or "",
                        url=finding_url,
                        port=parsed.port,
                        vuln_type=str(category),
                        severity=LEVEL.get(level, "info"),  # type: ignore[arg-type]
                        evidence={
                            "parameter": entry.get("parameter"),
                            "info": entry.get("info"),
                            "method": entry.get("method"),
                            "path": entry.get("path"),
                        },
                        raw=entry,
                    )
                )
        return output
