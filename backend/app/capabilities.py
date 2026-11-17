from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


CLI_TOOLS: dict[str, list[str]] = {
    "subfinder": ["subfinder", "-version"],
    "dnsx": ["dnsx", "-version"],
    "httpx": ["httpx", "-version"],
    "nmap": ["nmap", "--version"],
    "nuclei": ["nuclei", "-version"],
    "nikto": ["nikto", "-Version"],
    "wapiti": ["wapiti", "--version"],
    "schemathesis": ["schemathesis", "--version"],
    "kubescape": ["kubescape", "version"],
    "subjack": ["subjack", "-h"],
    "gitleaks": ["gitleaks", "version"],
}

ANSI_ESCAPE_RE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)
VERSION_PATTERNS: dict[str, str] = {
    "subfinder": r"Current Version:\s*v?([0-9][\w.\-]*)",
    "dnsx": r"Current Version:\s*v?([0-9][\w.\-]*)",
    "httpx": r"Current Version:\s*v?([0-9][\w.\-]*)",
    "nuclei": r"Nuclei Engine Version:\s*v?([0-9][\w.\-]*)",
    "nmap": r"Nmap version\s+([0-9][\w.\-]*)",
    "nikto": r"Nikto\s+([0-9][\w.\-]*)",
    "wapiti": r"(?m)^\s*v?([0-9]+(?:\.[0-9]+){1,3})\s*$",
    "schemathesis": r"version\s+([0-9][\w.\-]*)",
    "kubescape": r"current version is:\s*v?([0-9][\w.\-]*)",
    "gitleaks": r"(?m)^\s*v?([0-9]+(?:\.[0-9]+){1,3})\s*$",
}
STATIC_VERSIONS = {"subjack": "3.1.0"}


def _extract_version(name: str, value: str) -> str:
    cleaned = ANSI_ESCAPE_RE.sub("", value or "").replace("\r", "\n")
    pattern = VERSION_PATTERNS.get(name)
    if pattern:
        match = re.search(pattern, cleaned, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    if name in STATIC_VERSIONS:
        return STATIC_VERSIONS[name]

    for line in cleaned.splitlines():
        candidate = " ".join(line.split())
        if not candidate or candidate.startswith(("Usage:", "Options:")):
            continue
        if len(candidate) > 100:
            continue
        if re.search(r"[█╗╔║╚╝═┌┐└┘├┤┬┴┼]", candidate):
            continue
        if re.search(r"\d+\.\d+", candidate):
            return candidate
    return "installed"


def probe_capabilities() -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for name, command in CLI_TOOLS.items():
        executable = shutil.which(command[0])
        if not executable:
            output[name] = {
                "available": False,
                "version": "",
                "error": "tool_not_installed",
            }
            continue
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
                check=False,
            )
            output[name] = {
                "available": True,
                "version": _extract_version(
                    name,
                    "\n".join(
                        item
                        for item in (completed.stdout, completed.stderr)
                        if item
                    ),
                ),
                "error": None,
            }
        except Exception as exc:
            output[name] = {
                "available": True,
                "version": "",
                "error": str(exc),
            }

    zap_host = os.getenv("ZAP_HOST", "zap")
    zap_port = os.getenv("ZAP_PORT", "8090")
    output["zap"] = {
        **_probe_http_service(
            os.getenv("ZAP_URL", f"http://{zap_host}:{zap_port}"),
            "/JSON/core/view/version/",
            api_key=os.getenv("ZAP_API_KEY", ""),
        ),
        "version": "2.17.0",
        "mode": "external-service",
    }
    output["oast"] = {
        **_probe_http_service(
            os.getenv("OAST_URL", "http://oast:8001"),
            "/health",
        ),
        "version": "builtin-1",
        "mode": "external-service",
    }
    output["openvas"] = _probe_openvas()
    return output


def _probe_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _probe_openvas() -> dict[str, Any]:
    if os.getenv("OPENVAS_ENABLED", "").lower() != "true":
        return {
            "available": False,
            "version": "external-service",
            "error": "tool_not_installed",
            "mode": "external-service",
        }
    host = os.getenv("OPENVAS_HOST", "openvas")
    port = int(os.getenv("OPENVAS_PORT", "9390"))
    if not _probe_tcp(host, port):
        return {
            "available": False,
            "version": "external-service",
            "error": "service_unreachable",
            "mode": "external-service",
        }
    if not shutil.which("gvm-cli"):
        return {
            "available": False,
            "version": "external-service",
            "error": "gvm_cli_not_installed",
            "mode": "external-service",
        }
    try:
        username = os.getenv("OPENVAS_USERNAME", "admin")
        password = os.getenv("OPENVAS_PASSWORD", "admin")
        version_xml = _run_gvm_cli(host, port, username, password, "<get_version/>")
        version_root = ET.fromstring(version_xml)
        version = " ".join(
            (item.text or "").strip()
            for item in version_root.iter()
            if item.tag.rsplit("}", 1)[-1] == "version"
        ).strip() or "external-service"
        feeds_xml = _run_gvm_cli(host, port, username, password, "<get_feeds/>")
        root = ET.fromstring(feeds_xml)
        statuses = [
            (item.text or "").strip().lower()
            for item in root.iter()
            if item.tag.rsplit("}", 1)[-1] == "status"
        ]
        if any(
            "sync" in status or "update in progress" in status
            for status in statuses
        ):
            return {
                "available": False,
                "version": version,
                "error": "feed_not_synced",
                "mode": "external-service",
            }
        return {
            "available": True,
            "version": version,
            "error": None,
            "mode": "external-service",
        }
    except Exception as exc:
        return {
            "available": False,
            "version": "external-service",
            "error": str(exc),
            "mode": "external-service",
        }


def _run_gvm_cli(
    host: str,
    port: int,
    username: str,
    password: str,
    xml: str,
) -> str:
    tls_options: list[str] = []
    cafile = os.getenv("OPENVAS_CAFILE", "")
    if cafile:
        tls_options.extend(["--cafile", cafile])
    completed = subprocess.run(
        [
            "gvm-cli",
            "--gmp-username",
            username,
            "--gmp-password",
            password,
            "--timeout",
            "15",
            "tls",
            "--hostname",
            host,
            "--port",
            str(port),
            *tls_options,
            "--xml",
            xml,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            (completed.stderr or completed.stdout or "gvm-cli failed").strip()[-2000:]
        )
    return completed.stdout


def _probe_http_service(
    base_url: str,
    path: str,
    api_key: str = "",
    *,
    timeout: float = 5,
    attempts: int = 3,
) -> dict[str, Any]:
    if not base_url:
        return {"available": False, "error": "tool_not_installed"}
    query = urllib.parse.urlencode({"apikey": api_key} if api_key else {})
    url = f"{base_url.rstrip('/')}{path}"
    if query:
        url = f"{url}?{query}"
    last_error = ""
    for attempt in range(max(1, attempts)):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as response:
                if 200 <= response.status < 300:
                    return {"available": True, "error": None}
                last_error = f"unexpected_http_status: {response.status}"
        except Exception as exc:
            last_error = str(exc)
        if attempt + 1 < attempts:
            time.sleep(1)
    return {"available": False, "error": last_error}


def capabilities_path() -> Path:
    return Path(os.getenv("CAPABILITIES_PATH", "/output/capabilities.json"))


def write_capabilities() -> dict[str, dict[str, Any]]:
    output = probe_capabilities()
    path = capabilities_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    return output


def read_capabilities() -> dict[str, dict[str, Any]]:
    path = capabilities_path()
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass
    return probe_capabilities()
