from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..schemas.finding import Finding
from .base import BaseAdapter


class NmapAdapter(BaseAdapter):
    name = "nmap"
    tool_version = "7.93"

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        hosts = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        hosts = [str(item).strip() for item in hosts if str(item).strip()]
        if not self.available() or not hosts:
            return []
        findings: list[Finding] = []
        for host in hosts:
            completed = self._run(
                [
                    "nmap",
                    "-sT",
                    "-sV",
                    "-sC",
                    "-Pn",
                    "--max-rate",
                    str(self._rate(options) * 10),
                    "-oX",
                    "-",
                    host,
                ]
            )
            findings.extend(self.parse_output(completed.stdout, host))
            kubernetes_probe = self._run(
                [
                    "nmap",
                    "-sT",
                    "-Pn",
                    "-p",
                    "6443",
                    "-oX",
                    "-",
                    host,
                ]
            )
            findings.extend(self.parse_output(kubernetes_probe.stdout, host))
        unique: dict[tuple[str, int | None, str], Finding] = {}
        for finding in findings:
            unique[(finding.host, finding.port, finding.vuln_type)] = finding
        return self._filter_findings(list(unique.values()), options)

    @staticmethod
    def parse_output(text: str, fallback_host: str = "") -> list[Finding]:
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        findings: list[Finding] = []
        for host_elem in root.findall("host"):
            addresses = {
                item.get("addrtype"): item.get("addr")
                for item in host_elem.findall("address")
                if item.get("addr")
            }
            host = addresses.get("ipv4") or addresses.get("ipv6") or fallback_host
            for port_elem in host_elem.findall(".//port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port_elem.find("service")
                name = service.get("name") if service is not None else "unknown"
                product = service.get("product") if service is not None else ""
                version = service.get("version") if service is not None else ""
                port = int(port_elem.get("portid") or 0)
                label = f"{name} {product} {version}".strip()
                findings.append(
                    Finding(
                        source="nmap",
                        host=host,
                        port=port,
                        vuln_type="open_port",
                        severity="info",
                        evidence={"service": label, "protocol": port_elem.get("protocol")},
                        raw={"port": port, "service": name, "product": product},
                    )
                )
        return findings
