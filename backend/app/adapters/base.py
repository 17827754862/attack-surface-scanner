from __future__ import annotations

import ipaddress
import os
import shutil
import signal
import subprocess
from abc import ABC, abstractmethod
from typing import Any, Callable

from ..schemas.finding import Finding
from ..guard import GuardError, validate_scope


class AdapterCancelled(RuntimeError):
    pass


class BaseAdapter(ABC):
    name = "base"
    tool_version = "unknown"

    def __init__(
        self,
        capabilities: dict[str, dict[str, Any]] | None = None,
        cancel_check: Callable[[], bool] | None = None,
    ) -> None:
        self.capabilities = capabilities or {}
        self.cancel_check = cancel_check or (lambda: False)

    def available(self) -> bool:
        capability = self.capabilities.get(self.name)
        if capability is not None:
            return bool(capability.get("available"))
        return shutil.which(self.name) is not None

    @abstractmethod
    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        """Execute one adapter and return normalized, authorized findings."""

    def _run(
        self,
        command: list[str],
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self._check_cancel()
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
        if input_text is not None and process.stdin is not None:
            process.stdin.write(input_text)
            process.stdin.close()
            process.stdin = None
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.2)
                return subprocess.CompletedProcess(
                    command,
                    process.returncode,
                    stdout,
                    stderr,
                )
            except subprocess.TimeoutExpired:
                if self.cancel_check():
                    self._terminate(process)
                    raise AdapterCancelled("task cancelled")

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=3)
        except (AttributeError, ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (AttributeError, ProcessLookupError):
                pass

    def _check_cancel(self) -> None:
        if self.cancel_check():
            raise AdapterCancelled("task cancelled")

    def _rate(self, options: dict[str, Any]) -> int:
        try:
            return max(1, min(5, int(options.get("max_rps", 5))))
        except (TypeError, ValueError):
            return 5

    def _finding(
        self,
        *,
        host: str,
        vuln_type: str,
        severity: str = "info",
        url: str | None = None,
        port: int | None = None,
        evidence: dict[str, Any] | None = None,
        raw: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            source=self.name,
            host=host,
            url=url,
            port=port,
            vuln_type=vuln_type,
            severity=severity,  # type: ignore[arg-type]
            evidence=evidence or {},
            raw=raw or {},
        )

    def _trace(self, status: str, summary: str, error: str | None = None) -> dict[str, Any]:
        return {
            "tool_name": self.name,
            "status": status,
            "output_summary": summary,
            "error": error,
        }

    def _record_blocked(
        self,
        options: dict[str, Any],
        target: str,
        reason: str,
    ) -> None:
        blocked = options.setdefault("blocked_targets", [])
        value = f"{reason}: {target}"
        if value not in blocked:
            blocked.append(value)

    def _candidate_allowed(self, candidate: str, options: dict[str, Any]) -> bool:
        try:
            host = validate_scope(
                candidate,
                options.get("scope", []),
                options.get("allowed_cidrs", []),
            ).host
            return bool(host)
        except GuardError as exc:
            try:
                resolved = {
                    str(item)
                    for item in options.get("resolved_ips", [])
                    if str(item).strip()
                }
                if candidate in resolved:
                    return True
                address = ipaddress.ip_address(candidate)
                if str(address) in resolved:
                    return True
            except ValueError:
                pass
            try:
                host = candidate.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                if host in {
                    str(item)
                    for item in options.get("resolved_ips", [])
                    if str(item).strip()
                }:
                    return True
                address = ipaddress.ip_address(host)
                networks = [
                    ipaddress.ip_network(item, strict=False)
                    for item in options.get("allowed_cidrs", [])
                ]
                if any(address in network for network in networks):
                    return True
            except ValueError:
                pass
            self._record_blocked(options, candidate, str(exc))
            return False

    def _filter_findings(
        self,
        findings: list[Finding],
        options: dict[str, Any],
    ) -> list[Finding]:
        output: list[Finding] = []
        for finding in findings:
            candidate = finding.url or finding.host
            if candidate and self._candidate_allowed(candidate, options):
                output.append(finding)
            elif finding.host and self._candidate_allowed(finding.host, options):
                output.append(finding)
        return output
