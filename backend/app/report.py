from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Template

from .i18n import severity_labels, vuln_type_labels
from .playbooks import playbook_for
from .schemas.finding import Finding
from .workflow_image import render_workflow


HTML_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Attack Surface Report</title>
  <style>
    :root{--navy:#071426;--blue:#0b5cff;--ink:#eef4ff;--muted:#8494aa;--line:#17263b;--canvas:#04070d;--panel:#07101d;color-scheme:dark;scrollbar-color:#35353a #050506;scrollbar-width:thin}
    *{box-sizing:border-box}
    *::-webkit-scrollbar{width:10px;height:10px}
    *::-webkit-scrollbar-track{background:#050506}
    *::-webkit-scrollbar-thumb{background:#35353a;border:2px solid #050506;border-radius:8px}
    body{font-family:"HarmonyOS Sans SC","Microsoft YaHei",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;color:var(--ink);background:var(--canvas);line-height:1.6}
    main{max-width:1180px;margin:0 auto;padding:24px}
    .report-head{position:relative;overflow:hidden;background:linear-gradient(135deg,#061224,#0b2b57);padding:30px 32px;color:#fff;border:1px solid #173d6d}
    .report-head:after{position:absolute;right:-80px;bottom:-120px;width:320px;height:320px;content:"";border:1px solid rgba(106,161,246,.24);transform:rotate(24deg)}
    .report-kicker{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em;text-transform:uppercase;color:#78aaff}
    .report-head h1{max-width:900px;margin:16px 0 10px;font-size:38px;line-height:1.25;letter-spacing:0}
    .report-meta{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;color:#9db3d1;overflow-wrap:anywhere}
    .summary-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:14px 0 24px}
    .summary-card{background:var(--panel);border:1px solid var(--line);padding:15px}
    .summary-card span{display:block;color:var(--muted);font-size:13px}
    .summary-card strong{display:block;margin-top:8px;color:#f1f5ff;font:380 28px ui-monospace,SFMono-Regular,Menlo,monospace}
    h2{margin:34px 0 14px;padding-left:12px;border-left:3px solid var(--blue);color:#eaf1fd;font-size:22px;font-weight:600;line-height:1.35}
    h3{margin:20px 0 10px;color:#c7d7eb;font-size:17px;font-weight:600}
    p{font-size:14px;line-height:1.7;color:#91a3ba}
    table{width:100%;border-collapse:collapse;margin:12px 0 24px;background:var(--panel);border:1px solid var(--line)}
    th,td{border-bottom:1px solid #14243a;text-align:left;padding:12px;font-size:13px;line-height:1.6;vertical-align:top;color:#94a7be}
    th{background:#050b14;color:#7186a0;font:650 12px ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.05em;text-transform:uppercase}
    tr:last-child td{border-bottom:0}
    code,pre{white-space:pre-wrap;overflow-wrap:anywhere}
    code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#9bc2ff}
    pre{background:#07152b;border:1px solid #10294b;padding:16px;color:#b7cdea;font-size:13px;line-height:1.7}
    .muted{color:var(--muted)}
    details{margin:10px 0;background:var(--panel);border:1px solid var(--line);padding:0}
    details>summary{cursor:pointer;padding:14px 16px;font-size:14px;font-weight:600;color:#d4e1f1}
    details>h3,details>p,details>pre,details>ol,details>ul{margin-left:14px;margin-right:14px}
    .playbook{background:#071426;border-left:2px solid var(--blue);color:#89a6cb;padding:12px}
    .badge{display:inline-block;background:#07101d;border:1px solid #1c2d45;color:#8da2bb;padding:3px 8px;margin:3px 5px 3px 0;font-size:11px}
    ul,ol{padding-left:22px}
    li{margin:6px 0;font-size:13px;line-height:1.65;color:#8ea2ba}
    .severity-critical{color:#a70f23}.severity-high{color:#c62c3b}.severity-medium{color:#a46606}
  </style>
</head>
<body><main>
  <header class="report-head">
    <div class="report-kicker">Authorized assessment / deterministic evidence</div>
    <h1>攻击面侦察与漏洞定位报告 / Attack Surface Assessment Report</h1>
    <div class="report-meta">Task {{ task_id }} · {{ target }} · STATUS {{ status }}</div>
  </header>
  <div class="summary-grid">
    <div class="summary-card"><span>Finding 实例</span><strong>{{ summary_counts.findings }}</strong></div>
    <div class="summary-card"><span>风险组</span><strong>{{ summary_counts.risk_groups }}</strong></div>
    <div class="summary-card"><span>高危及严重</span><strong>{{ summary_counts.high_risk }}</strong></div>
    <div class="summary-card"><span>执行节点</span><strong>{{ summary_counts.nodes }}</strong></div>
  </div>
  {% if budget_context %}
  <h2>执行策略 / Execution Policy</h2>
  <p class="muted">
    Time limit: none ·
    Validation: {{ budget_context.validation_level or "safe" }} ·
    OAST: {{ "enabled" if budget_context.oast_enabled else "disabled" }}
  </p>
  {% endif %}
  {% if routing_context %}
  <h2>动态扫描编排 / Adaptive Routing</h2>
  <p class="muted">
    Mode: {{ routing_context.mode or "auto" }} ·
    Confidence: {{ routing_context.confidence or 0 }} ·
    Completed tools: {{ (routing_context.completed_scan_nodes or [])|join(", ") or "-" }}
  </p>
  {% if routing_context.reason %}<p>{{ routing_context.reason }}</p>{% endif %}
  {% if routing_context.decisions %}
  <table><thead><tr><th>Step</th><th>Tool</th><th>Source</th><th>Reason</th><th>Confidence</th></tr></thead><tbody>
  {% for item in routing_context.decisions %}
    <tr>
      <td>{{ item.step }}</td>
      <td>{{ item.node }}</td>
      <td>{{ item.source }}</td>
      <td>{{ item.reason or "-" }}</td>
      <td>{{ item.confidence or 0 }}</td>
    </tr>
  {% endfor %}
  </tbody></table>
  {% endif %}
  {% endif %}
  {% if memory_context %}
  <h2>历史记忆 / Historical Memory</h2>
  <p class="muted">
    Previous scans: {{ memory_context.scan_count or 0 }} ·
    New risks: {{ memory_context.new_risk_types|length }} ·
    Persistent: {{ memory_context.persistent_risk_types|length }} ·
    Resolved: {{ memory_context.resolved_risk_types|length }}
  </p>
  {% if memory_context.new_risk_types %}<p>新增 / New: {{ memory_context.new_risk_types|join(", ") }}</p>{% endif %}
  {% if memory_context.resolved_risk_types %}<p>已消失 / Resolved: {{ memory_context.resolved_risk_types|join(", ") }}</p>{% endif %}
  {% endif %}
  {% if llm_summary and llm_summary.text %}
  <h2>AI 辅助研判 / AI-assisted Analysis</h2>
  <pre class="playbook">{{ llm_summary.text }}</pre>
  {% endif %}
  {% if benchmark_context %}
  <h2>靶场基准召回率 / Lab Benchmark Recall</h2>
  <div class="summary-grid">
    <div class="summary-card"><span>Ground truth 项</span><strong>{{ benchmark_context.total }}</strong></div>
    <div class="summary-card"><span>确认命中</span><strong>{{ benchmark_context.matched }}</strong></div>
    <div class="summary-card"><span>漏报</span><strong>{{ benchmark_context.missed }}</strong></div>
    <div class="summary-card"><span>Recall</span><strong>{{ benchmark_context.recall_percent }}%</strong></div>
  </div>
  <p class="muted">{{ benchmark_context.name }} · {{ benchmark_context.official_scope }} · 85% target: {{ "met" if benchmark_context.target_met else "not met" }}</p>
  <table><thead><tr><th>GT ID</th><th>Known issue</th><th>Result</th></tr></thead><tbody>
  {% for item in benchmark_context["items"] %}
    <tr><td><code>{{ item.id }}</code></td><td>{{ item.name }}</td><td>{{ "matched" if item.matched else "missed" }}</td></tr>
  {% endfor %}
  </tbody></table>
  {% endif %}
  <h2>风险组 / Risk Groups</h2>
  <table><thead><tr><th>Severity</th><th>Risk</th><th>Instances</th><th>Affected URLs</th><th>Sources</th><th>Analysis</th></tr></thead><tbody>
  {% for group in risk_groups %}
    <tr>
      <td>{{ group.severity_zh }} / {{ group.severity_en }}</td>
      <td>{{ group.title_zh }} / {{ group.title_en }}</td>
      <td>{{ group.instance_count }}</td>
      <td>{{ group.affected_url_count }}</td>
      <td>{{ group.sources|join(", ") }}</td>
      <td>{{ group.analysis_source }}</td>
    </tr>
  {% endfor %}
  </tbody></table>
  {% for group in risk_groups %}
  <details>
    <summary>{{ group.severity_zh }} / {{ group.severity_en }} · {{ group.title_zh }} / {{ group.title_en }}</summary>
    {% if group.description_zh or group.description_en %}
    <h3>解读 / Interpretation</h3>
    <p>{{ group.description_zh }}</p>
    <p class="muted">{{ group.description_en }}</p>
    {% endif %}
    {% if group.impact_zh or group.impact_en %}
    <h3>影响 / Impact</h3>
    <p>{{ group.impact_zh }}</p>
    <p class="muted">{{ group.impact_en }}</p>
    {% endif %}
    {% if group.reproduction_steps_zh or group.reproduction_steps_en %}
    <h3>复现验证 / Verification</h3>
    <ol>
    {% for step in group.reproduction_steps_zh %}<li>{{ step }}</li>{% endfor %}
    {% for step in group.reproduction_steps_en %}<li class="muted">{{ step }}</li>{% endfor %}
    </ol>
    {% endif %}
    {% if group.false_positive_checks_zh %}
    <h3>误报检查 / False-positive Checks</h3>
    <ul>{% for step in group.false_positive_checks_zh %}<li>{{ step }}</li>{% endfor %}</ul>
    {% endif %}
    {% if group.remediation_zh %}
    <h3>修复 / Remediation</h3>
    <ul>{% for step in group.remediation_zh %}<li>{{ step }}</li>{% endfor %}</ul>
    {% endif %}
    <h3>受影响 URL / Affected URLs</h3>
    <ul>{% for url in group.affected_urls %}<li><code>{{ url }}</code></li>{% endfor %}</ul>
    <p class="muted">{% for source in group.sources %}<span class="badge">{{ source }}</span>{% endfor %}</p>
  </details>
  {% endfor %}
  <h2>节点状态 / Node Status</h2>
  <table><thead><tr><th>节点</th><th>状态</th></tr></thead><tbody>
  {% for node, state in visible_node_status.items() %}<tr><td>{{ node }}</td><td>{{ state }}</td></tr>{% endfor %}
  </tbody></table>
  <h2>Finding 实例 / Finding Instances</h2>
  <table><thead><tr><th>Confidence</th><th>Severity</th><th>Type</th><th>Host</th><th>URL</th><th>Sources</th><th>Evidence SHA-256</th></tr></thead><tbody>
  {% for item in findings %}<tr><td>{{ item.confidence }}</td><td>{{ item.severity_zh }} / {{ item.severity_en }}</td><td>{{ item.vuln_type_zh }} / {{ item.vuln_type_en }}</td><td>{{ item.host }}</td><td>{{ item.url or "-" }}</td><td>{{ item.source }}{% if item.also_reported_by %}, {{ item.also_reported_by|join(", ") }}{% endif %}</td><td><code>{{ item.evidence_hash }}</code></td></tr>{% endfor %}
  </tbody></table>
  {% for item in findings %}
  <details>
    <summary>{{ item.confidence }}/100 · {{ item.severity_zh }} / {{ item.severity_en }} · {{ item.vuln_type_zh }} / {{ item.vuln_type_en }}</summary>
    <h3>证据 / Evidence</h3>
    <pre>{{ item.evidence | tojson }}</pre>
    {% if item.playbook_content %}
      <h3>情景化处置 / Playbook：{{ item.playbook }}</h3>
    <pre class="playbook">{{ item.playbook_content }}</pre>
    {% endif %}
  </details>
  {% endfor %}
  {% if blocked_targets %}
    <h2>已拦截越界目标 / Blocked Out-of-scope Targets</h2>
  <ul>{% for target in blocked_targets %}<li><code>{{ target }}</code></li>{% endfor %}</ul>
  {% endif %}
  <h2>覆盖范围说明 / Coverage</h2>
  <ul>
    <li>目标范围为任务提交时授权的本地目标；所有重定向、OpenAPI 服务地址和工具返回地址均经过 Scope Guard。</li>
    <li>Subfinder、dnsx 和 httpx 负责资产发现；Nmap 负责服务与端口；Nuclei 只报告固定模板集中的已知风险。</li>
    <li>ZAP 负责 Web 动态检查，Wapiti 负责参数级 SQLi、XSS、文件、上传与 CSRF 检查，Nikto 补充服务器配置问题。</li>
    <li>通用认证分析检查会话轮换、弱会话标识、配置化弱口令和低量登录限速；深度模式可启用无载荷上传、SQL 参数差分、低影响命令回显与 OAST 回调验证。</li>
    <li>Schemathesis、Kubescape、Gitleaks、Subjack 和 OpenVAS 按目标条件或运行 profile 启用，未启用节点会明确标记 skipped。</li>
    <li>报告不覆盖需要人工业务流程建模的逻辑漏洞，也不会执行漏洞利用、口令爆破或横向移动。</li>
  </ul>
  <h2>工作流</h2>
  <p class="muted">工作流图片由报告页面使用鉴权后的二进制请求单独加载；下方保留离线 Mermaid 源。</p>
  <pre>{{ mermaid }}</pre>
</main></body></html>
"""


def render_report(
    task_id: str,
    target: str,
    status: str,
    findings: list[Finding],
    node_status: dict[str, str],
    trace: list[dict[str, Any]],
    output_dir: str,
    llm_summary: dict[str, Any] | None = None,
    blocked_targets: list[str] | None = None,
    risk_groups: list[dict[str, Any]] | None = None,
    memory_context: dict[str, Any] | None = None,
    budget_context: dict[str, Any] | None = None,
    routing_context: dict[str, Any] | None = None,
    benchmark_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    workflow = render_workflow(task_id, trace, node_status, output_dir)
    mmd = Path(workflow["mermaid"]).read_text(encoding="utf-8")
    finding_rows = []
    for item in findings:
        row = item.model_dump()
        filename, content = playbook_for(item.vuln_type)
        row["playbook"] = filename or item.playbook
        row["playbook_content"] = content
        row["severity_zh"], row["severity_en"] = severity_labels(item.severity)
        row["vuln_type_zh"], row["vuln_type_en"] = vuln_type_labels(item.vuln_type)
        finding_rows.append(row)
    group_rows = []
    for group in risk_groups or []:
        row = dict(group)
        row["severity_zh"], row["severity_en"] = severity_labels(
            str(row.get("severity") or "info")
        )
        group_rows.append(row)
    visible_node_status = {
        node: state
        for node, state in node_status.items()
        if str(state or "pending").lower() not in {"pending", "skipped", "cancelled"}
    }
    summary_counts = {
        "findings": len(finding_rows),
        "risk_groups": len(group_rows),
        "high_risk": sum(
            1 for row in finding_rows if row.get("severity") in {"critical", "high"}
        ),
        "nodes": len(visible_node_status),
    }
    html = Template(HTML_TEMPLATE, autoescape=True).render(
        task_id=task_id,
        target=target,
        status=status,
        findings=finding_rows,
        node_status=node_status,
        visible_node_status=visible_node_status,
        workflow_png=workflow["png"],
        mermaid=mmd,
        llm_summary=llm_summary or {},
        blocked_targets=blocked_targets or [],
        risk_groups=group_rows,
        memory_context=memory_context or {},
        budget_context=budget_context or {},
        routing_context=routing_context or {},
        benchmark_context=benchmark_context or {},
        summary_counts=summary_counts,
    )
    root = Path(output_dir) / task_id
    root.mkdir(parents=True, exist_ok=True)
    html_path = root / "report.html"
    json_path = root / "report.json"
    findings_path = root / "findings.json"
    html_path.write_text(html, encoding="utf-8")
    findings_path.write_text(
        json.dumps(finding_rows, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    payload = {
        "task_id": task_id,
        "target": target,
        "status": status,
        "node_status": node_status,
        "execution_trace": trace,
        "findings": finding_rows,
        "workflow": workflow,
        "mermaid": mmd,
        "llm_summary": llm_summary or {},
        "blocked_targets": blocked_targets or [],
        "risk_groups": group_rows,
        "memory_context": memory_context or {},
        "budget_context": budget_context or {},
        "routing_context": routing_context or {},
        "benchmark_context": benchmark_context or {},
        "routing_mode": (routing_context or {}).get("mode", "auto"),
        "routing_reason": (routing_context or {}).get("reason", ""),
        "routing_confidence": int((routing_context or {}).get("confidence") or 0),
        "scan_decisions": (routing_context or {}).get("decisions") or [],
        "summary_counts": summary_counts,
    }
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        "html": str(html_path),
        "json": str(json_path),
        "findings_json": str(findings_path),
        **workflow,
    }
