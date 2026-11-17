from __future__ import annotations

import html
import math
import os
import re
from pathlib import Path
from typing import Any


NODE_META = {
    "auth_gate": ("授权门禁", "Authorization", "guard"),
    "recon": ("资产发现", "Asset discovery", "subfinder"),
    "dns_resolve": ("DNS 解析", "DNS resolution", "dnsx"),
    "takeover_check": ("子域接管", "Takeover check", "subjack"),
    "http_probe": ("HTTP 探测", "HTTP probing", "httpx"),
    "port_scan": ("端口服务", "Port scan", "nmap"),
    "credential_session_analysis": (
        "认证会话",
        "Auth & session",
        "auth analyzer",
    ),
    "router": ("条件路由", "Conditional router", "decision"),
    "web_scan": ("Web 动态扫描", "Active web scan", "zap"),
    "nuclei_scan": ("模板漏洞", "Template scan", "nuclei"),
    "js_secret_scan": ("前端密钥", "Secret scan", "gitleaks"),
    "api_fuzz": ("API 契约", "API contract", "schemathesis"),
    "k8s_audit": ("K8s 基线", "K8s audit", "kubescape"),
    "server_baseline": ("服务器基线", "Server baseline", "nikto + wapiti"),
    "active_validation": ("主动验证", "Active validation", "safe validators"),
    "host_vuln_scan": ("主机漏洞", "Host vulnerabilities", "openvas"),
    "merge_and_score": ("归一化评分", "Merge & score", "dedup"),
    "llm_summarize": ("AI 研判", "AI analysis", "optional llm"),
    "report": ("报告生成", "Report", "jinja2 + mermaidx"),
}

NODE_TOOL = {node: values[2] for node, values in NODE_META.items()}
SCAN_NODES = (
    "web_scan",
    "nuclei_scan",
    "js_secret_scan",
    "api_fuzz",
    "k8s_audit",
    "server_baseline",
    "active_validation",
    "host_vuln_scan",
)
STATUS_CLASS = {
    "done": "done",
    "completed": "done",
    "running": "running",
    "resuming": "running",
    "failed": "failed",
    "blocked": "failed",
    "skipped": "skipped",
    "pending": "pending",
    "queued": "pending",
    "cancelled": "skipped",
}
WORKFLOW_FONT_FAMILY = "WorkflowSans"
WORKFLOW_FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    r"C:\Windows\Fonts\simhei.ttf",
    r"C:\Windows\Fonts\msyh.ttc",
)
_workflow_font_family = ""


def _summary(value: Any, limit: int = 54) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return html.escape(text, quote=True)


def _label(node: str, summary: str, sequence: int) -> str:
    title_zh, title_en, tool = NODE_META[node]
    label = (
        f"<small>STEP {sequence:02d}</small><br/>"
        f"{title_zh}<br/>{title_en}<br/><b>{html.escape(tool)}</b>"
    )
    if summary:
        label += f"<br/>{_summary(summary)}"
    return label


def _workflow_font() -> str:
    global _workflow_font_family
    if _workflow_font_family:
        return _workflow_font_family
    configured = os.getenv("WORKFLOW_CJK_FONT", "").strip()
    candidates = (configured, *WORKFLOW_FONT_CANDIDATES) if configured else WORKFLOW_FONT_CANDIDATES
    path = next((item for item in candidates if item and Path(item).is_file()), "")
    if not path:
        return ""
    try:
        import novasvg.fonts as fonts

        fonts.add_font_face_from_file("WorkflowSans", False, False, path)
        fonts.add_font_face_from_file("WorkflowSans", True, False, path)
        _workflow_font_family = "WorkflowSans"
    except Exception:
        return ""
    return _workflow_font_family


def _visible_trace(
    trace: list[dict[str, Any]],
    node_status: dict[str, str],
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    order: list[str] = []
    entries: dict[str, dict[str, Any]] = {}
    for item in trace:
        node = str(item.get("node_name") or "")
        if node not in NODE_META:
            continue
        status = str(item.get("status") or "done").lower()
        if status in {"skipped", "pending", "cancelled"}:
            continue
        if node not in entries:
            order.append(node)
        entries[node] = {
            "status": status,
            "summary": str(item.get("output_summary") or ""),
            "error": str(item.get("error") or ""),
        }
    for node, status in node_status.items():
        if node not in NODE_META or node in entries:
            continue
        state = str(status or "pending").lower()
        if state in {"pending", "skipped", "cancelled"}:
            continue
        order.append(node)
        entries[node] = {"status": state, "summary": "", "error": ""}
    return order, entries


def build_mermaid(trace: list[dict[str, Any]], node_status: dict[str, str]) -> str:
    order, entries = _visible_trace(trace, node_status)
    lines = [
        f'%%{{init: {{"theme":"base","themeVariables":{{"fontFamily":"{WORKFLOW_FONT_FAMILY}","fontSize":"14px","lineColor":"#3f536d","edgeLabelBackground":"#050506","background":"#050506","primaryColor":"#0e0e10","primaryTextColor":"#e5e7eb","primaryBorderColor":"#35353a","clusterBkg":"#09090b","clusterBorder":"#29292d"}},"flowchart":{{"curve":"basis","htmlLabels":true,"nodeSpacing":42,"rankSpacing":74}}}}}}%%',
        "flowchart TB",
        "  classDef done fill:#071812,stroke:#2c8d72,stroke-width:2px,color:#c2f56a",
        "  classDef running fill:#07152b,stroke:#2878ff,stroke-width:2px,color:#9bc2ff",
        "  classDef failed fill:#1c0a0e,stroke:#ff6f7f,stroke-width:2px,color:#ffb0b9",
        "  classDef skipped fill:#0d0d0f,stroke:#35353a,stroke-width:1px,color:#6b7280,stroke-dasharray:5 5",
        "  classDef pending fill:#171006,stroke:#8d662a,stroke-width:1px,color:#ffc761",
        "  classDef terminal fill:#2878ff,stroke:#2878ff,stroke-width:2px,color:#ffffff",
        '  START(["开始扫描<br/>Scan start"]):::terminal',
    ]
    if not order:
        lines.extend(
            [
                '  subgraph ROW1["01 执行阶段 / Execution stage"]',
                "    direction TB",
                '    EMPTY["尚未产生扫描数据"]:::pending',
                "    START --> EMPTY",
                "  end",
                "  style ROW1 fill:#09090b,stroke:#29292d,color:#8a8a92",
            ]
        )
        return "\n".join(lines)

    row_count = 1 if len(order) <= 6 else 2 if len(order) <= 10 else 3
    row_size = math.ceil(len(order) / row_count)
    rows = [order[index : index + row_size] for index in range(0, len(order), row_size)]

    for row_index, row in enumerate(rows, start=1):
        lines.append(
            f'  subgraph ROW{row_index}["{row_index:02d} 串行执行链 / Sequential chain"]'
        )
        lines.append("    direction LR")
        for index, node in enumerate(row, start=1):
            entry = entries[node]
            sequence = (row_index - 1) * row_size + index
            label = _label(node, entry.get("summary", ""), sequence)
            if node == "router":
                lines.append(f'    {node}{{{{"{label}"}}}}')
            elif node == "report":
                lines.append(f'    {node}(["{label}"])')
            else:
                lines.append(f'    {node}["{label}"]')
        if row_index == 1:
            lines.append(f"    START --> {row[0]}")
        for current, next_node in zip(row, row[1:]):
            lines.append(f"    {current} --> {next_node}")
        lines.append("  end")
    for previous, current in zip(rows, rows[1:]):
        lines.append(f"  {previous[-1]} --> {current[0]}")
    for node in order:
        state = str(entries[node].get("status") or node_status.get(node) or "pending").lower()
        lines.append(f"  class {node} {STATUS_CLASS.get(state, 'pending')}")
    for row_index in range(1, len(rows) + 1):
        lines.append(
            f"  style ROW{row_index} fill:#09090b,stroke:#29292d,color:#8a8a92"
        )
    lines.append("  linkStyle default stroke:#3f536d,stroke-width:1.4px")
    return "\n".join(lines)


def render_workflow(
    task_id: str,
    trace: list[dict[str, Any]],
    node_status: dict[str, str],
    output_dir: str,
) -> dict[str, str | None]:
    root = Path(output_dir) / task_id
    root.mkdir(parents=True, exist_ok=True)
    mmd = build_mermaid(trace, node_status)
    mmd_path = root / "workflow.mmd"
    mmd_path.write_text(mmd, encoding="utf-8")
    png_path = root / "workflow.png"
    os.environ.setdefault("TMPDIR", "/tmp")
    try:
        import mermaidx

        _workflow_font()
        rendered = mermaidx.render(
            mmd,
            theme="base",
            config={
                "themeVariables": {
                    "fontFamily": WORKFLOW_FONT_FAMILY,
                    "background": "#050506",
                    "primaryColor": "#0e0e10",
                    "primaryTextColor": "#e5e7eb",
                    "primaryBorderColor": "#35353a",
                    "lineColor": "#3f536d",
                    "edgeLabelBackground": "#050506",
                    "clusterBkg": "#09090b",
                    "clusterBorder": "#29292d",
                },
                "flowchart": {
                    "curve": "basis",
                    "htmlLabels": True,
                    "nodeSpacing": 34,
                    "rankSpacing": 58,
                }
            },
        )
        rendered.save(
            str(png_path),
            scale=2.0,
            background="#050506",
        )
    except Exception:
        png_path = None
    return {
        "mermaid": str(mmd_path),
        "png": str(png_path) if png_path else None,
    }
