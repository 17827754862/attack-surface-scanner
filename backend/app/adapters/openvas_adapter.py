from __future__ import annotations

import os
import time
import xml.etree.ElementTree as ET
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from ..config import settings
from ..guard import normalize_target
from ..schemas.finding import Finding
from .base import AdapterCancelled, BaseAdapter


class OpenvasAdapter(BaseAdapter):
    name = "openvas"
    tool_version = "gvm-tools-26.0.7"

    def available(self) -> bool:
        if not settings.openvas_enabled:
            return False
        capability = self.capabilities.get(self.name)
        return bool(capability.get("available")) if capability is not None else True

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        if not self.available():
            return []
        target_host = normalize_target(str(target_or_input))
        findings: list[Finding] = []
        target_id = ""
        task_id = ""
        try:
            configs = self._xml(self._call("<get_configs/>"))
            scanners = self._xml(self._call("<get_scanners/>"))
            config_id = self._first_id(configs, "config", "Full and fast")
            scanner_id = self._first_id(scanners, "scanner", "OpenVAS Default")
            if not config_id or not scanner_id:
                raise RuntimeError("OpenVAS config or scanner is unavailable")

            suffix = str(int(time.time()))
            target_response = self._xml(
                self._call(
                    "<create_target>"
                    f"<name>scanner-{suffix}</name>"
                    f"<hosts>{escape(target_host)}</hosts>"
                    "<port_range>T:1-65535</port_range>"
                    "</create_target>"
                )
            )
            target_id = self._first_attr(target_response, "target", "id")
            task_response = self._xml(
                self._call(
                    "<create_task>"
                    f"<name>scanner-{suffix}</name>"
                    f"<config id={quoteattr(config_id)}/>"
                    f"<target id={quoteattr(target_id)}/>"
                    f"<scanner id={quoteattr(scanner_id)}/>"
                    "<preferences>"
                    "<preference><name>max_hosts</name><value>1</value></preference>"
                    f"<preference><name>max_checks</name><value>{self._rate(options)}</value></preference>"
                    "</preferences>"
                    "</create_task>"
                )
            )
            task_id = self._first_attr(task_response, "task", "id")

            self._call(f"<start_task task_id={quoteattr(task_id)}/>")
            report_id = self._wait_for_report(task_id)
            report = self._xml(
                self._call(f"<get_report report_id={quoteattr(report_id)}/>")
            )
            findings = self.parse_results(report, target_host)
        except AdapterCancelled:
            if task_id:
                self._safe_call(f"<stop_task task_id={quoteattr(task_id)}/>")
            raise
        except Exception as exc:
            if task_id:
                self._safe_call(f"<stop_task task_id={quoteattr(task_id)}/>")
            raise RuntimeError(f"OpenVAS scan failed: {exc}") from exc
        finally:
            if task_id:
                self._safe_call(f"<delete_task task_id={quoteattr(task_id)} ultimate=\"1\"/>")
            if target_id:
                self._safe_call(
                    f"<delete_target target_id={quoteattr(target_id)} ultimate=\"1\"/>"
                )
        return self._filter_findings(findings, options)

    def _call(self, xml: str) -> str:
        tls_options: list[str] = []
        cafile = os.getenv("OPENVAS_CAFILE", "")
        if cafile:
            tls_options.extend(["--cafile", cafile])
        command = [
            "gvm-cli",
            "--gmp-username",
            settings.openvas_username,
            "--gmp-password",
            settings.openvas_password,
            "tls",
            "--hostname",
            settings.openvas_host,
            "--port",
            str(settings.openvas_port),
            *tls_options,
            "--xml",
            xml,
        ]
        completed = self._run(command)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "unknown gvm-cli error").strip()
            raise RuntimeError(detail[-2000:])
        return completed.stdout

    def _safe_call(self, xml: str) -> None:
        try:
            self._call(xml)
        except Exception:
            return

    @staticmethod
    def _xml(value: str) -> ET.Element:
        try:
            return ET.fromstring(value)
        except ET.ParseError as exc:
            raise RuntimeError("gvm-cli returned malformed XML") from exc

    @staticmethod
    def _first_attr(payload: ET.Element, tag: str, attribute: str) -> str:
        root_value = payload.get(attribute)
        if root_value:
            return str(root_value)
        for item in payload.iter():
            if item.tag.rsplit("}", 1)[-1] != tag:
                continue
            value = item.get(attribute)
            if value:
                return str(value)
        raise RuntimeError(f"OpenVAS response has no {tag}/{attribute}")

    @classmethod
    def _first_id(cls, payload: ET.Element, tag: str, preferred: str) -> str:
        rows = [
            item
            for item in payload.iter()
            if item.tag.rsplit("}", 1)[-1] == tag
        ]
        for item in rows:
            name = (item.findtext("name") or "").strip()
            value = item.get("id")
            if value and preferred.lower() in name.lower():
                return str(value)
        for item in rows:
            value = item.get("id")
            if value:
                return str(value)
        return ""

    def _wait_for_report(self, task_id: str) -> str:
        while True:
            self._check_cancel()
            task = self._xml(
                self._call(f"<get_tasks task_id={quoteattr(task_id)}/>")
            )
            for item in task.iter():
                if item.tag.rsplit("}", 1)[-1] != "report":
                    continue
                report_id = item.get("id")
                if report_id and item.findtext("scan_end"):
                    return str(report_id)
                if report_id and (item.findtext("timestamp") or ""):
                    return str(report_id)
            status = " ".join(
                (item.text or "")
                for item in task.iter()
                if item.tag.rsplit("}", 1)[-1] == "status"
            ).lower()
            if "stopped" in status or "failed" in status:
                raise RuntimeError(f"OpenVAS task ended with status {status!r}")
            time.sleep(10)

    @classmethod
    def parse_results(cls, payload: ET.Element | str, fallback_host: str) -> list[Finding]:
        if isinstance(payload, str):
            try:
                root = ET.fromstring(payload)
            except ET.ParseError:
                return []
        else:
            root = payload
        output: list[Finding] = []
        for result in root.findall(".//result"):
            name = result.findtext("name") or "OpenVAS finding"
            host = result.findtext("host") or fallback_host
            severity_text = result.findtext("severity") or "0"
            try:
                cvss = float(severity_text)
            except ValueError:
                cvss = 0.0
            if cvss >= 9:
                severity = "critical"
            elif cvss >= 7:
                severity = "high"
            elif cvss >= 4:
                severity = "medium"
            elif cvss > 0:
                severity = "low"
            else:
                severity = "info"
            port_text = result.findtext("port") or ""
            port = None
            if "/tcp" in port_text:
                value = port_text.split("/", 1)[0]
                if value.isdigit():
                    port = int(value)
            output.append(
                Finding(
                    source="openvas",
                    host=host,
                    port=port,
                    vuln_type=name,
                    severity=severity,  # type: ignore[arg-type]
                    evidence={
                        "cvss": cvss,
                        "port": port_text,
                        "description": result.findtext("description"),
                        "solution": result.findtext("solution"),
                        "nvt_oid": result.findtext("nvt/oid"),
                    },
                    raw={"xml": ET.tostring(result, encoding="unicode")},
                )
            )
        return output
