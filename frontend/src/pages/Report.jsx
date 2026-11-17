import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  Download,
  FileJson,
  FileText,
  GitBranch,
  Image as ImageIcon,
  Layers3,
  Maximize2,
  RefreshCw,
  ShieldAlert,
  X,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";
import mermaid from "mermaid";
import { downloadFile } from "../api";
import AppShell from "../components/AppShell";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import { statusLabels } from "../i18n";


export default function Report() {
  const { id } = useParams();
  const [html, setHtml] = useState("");
  const [reportJson, setReportJson] = useState(null);
  const [pngUrl, setPngUrl] = useState("");
  const [mmd, setMmd] = useState("");
  const [error, setError] = useState("");
  const [workflowOpen, setWorkflowOpen] = useState(false);
  const [workflowZoom, setWorkflowZoom] = useState(1);
  const [generatingWorkflow, setGeneratingWorkflow] = useState(false);
  const renderRef = useRef(null);
  const objectUrlRef = useRef("");

  useEffect(() => {
    async function load() {
      try {
        const token = localStorage.getItem("attack_surface_token") || "";
        const headers = { Authorization: `Bearer ${token}` };
        const [htmlResponse, jsonResponse, pngResponse] = await Promise.all([
          fetch(`/api/tasks/${id}/report`, { cache: "no-store", headers }),
          fetch(`/api/tasks/${id}/report?format=json`, { cache: "no-store", headers }),
          fetch(`/api/tasks/${id}/workflow.png`, { cache: "no-store", headers }),
        ]);

        if (htmlResponse.ok) setHtml(await htmlResponse.text());
        if (jsonResponse.ok) setReportJson(await jsonResponse.json());

        if (pngResponse.ok) {
          if (objectUrlRef.current) URL.revokeObjectURL(objectUrlRef.current);
          objectUrlRef.current = URL.createObjectURL(await pngResponse.blob());
          setPngUrl(objectUrlRef.current);
        } else {
          const graph = await fetch(`/api/tasks/${id}/graph.mmd`, {
            cache: "no-store",
            headers,
          });
          if (graph.ok) setMmd(await graph.text());
        }
        if (!htmlResponse.ok && !jsonResponse.ok) throw new Error("报告尚未生成");
      } catch (err) {
        setError(err.message);
      }
    }
    load();
    return () => {
      if (objectUrlRef.current) URL.revokeObjectURL(objectUrlRef.current);
      objectUrlRef.current = "";
    };
  }, [id]);

  useEffect(() => {
    if (!mmd || !renderRef.current) return;
    mermaid.initialize({
      startOnLoad: false,
      theme: "base",
      themeVariables: {
        fontFamily: "Segoe UI, Microsoft YaHei, sans-serif",
        fontSize: "14px",
        background: "#050506",
        primaryColor: "#0e0e10",
        primaryTextColor: "#e5e7eb",
        primaryBorderColor: "#35353a",
        lineColor: "#3f536d",
        edgeLabelBackground: "#050506",
        clusterBkg: "#09090b",
        clusterBorder: "#29292d",
      },
      flowchart: { curve: "basis", htmlLabels: true },
    });
    mermaid.render(`workflow-${id}`, mmd).then(({ svg }) => {
      if (renderRef.current) renderRef.current.innerHTML = svg;
    });
  }, [id, mmd]);

  useEffect(() => {
    if (!workflowOpen) return undefined;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKeyDown = (event) => {
      if (event.key === "Escape") setWorkflowOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [workflowOpen]);

  const findings = reportJson?.findings || [];
  const riskGroups = reportJson?.risk_groups || [];
  const severity = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) {
      const key = finding.severity || "info";
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, [findings]);
  const status = reportJson?.status || "completed";

  async function regenerateWorkflow() {
    setGeneratingWorkflow(true);
    setError("");
    try {
      const token = localStorage.getItem("attack_surface_token") || "";
      const response = await fetch(`/api/tasks/${id}/workflow/regenerate`, {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!response.ok) {
        let detail = "";
        try {
          detail = (await response.json()).detail || "";
        } catch {
          detail = await response.text();
        }
        throw new Error(detail || `生成失败：HTTP ${response.status}`);
      }
      if (objectUrlRef.current) URL.revokeObjectURL(objectUrlRef.current);
      objectUrlRef.current = URL.createObjectURL(await response.blob());
      setPngUrl(objectUrlRef.current);
      setMmd("");
      setWorkflowZoom(1);
      setWorkflowOpen(true);
    } catch (err) {
      setError(err.message);
    } finally {
      setGeneratingWorkflow(false);
    }
  }

  async function download(kind) {
    try {
      if (kind === "png") {
        await downloadFile(`/api/tasks/${id}/workflow.png`, `workflow-${id}.png`);
      } else {
        await downloadFile(`/api/tasks/${id}/report?format=json`, `report-${id}.json`);
      }
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <AppShell>
      <main className="page-shell">
        <PageHeader
          eyebrow="Assessment report"
          title={reportJson?.target || "评估报告"}
          description={`task_id: ${id} · 确定性扫描结果、证据链与修复建议`}
          actions={(
            <>
              <StatusBadge status={status} label={statusLabels[status] || status} />
              <span className={`status-badge ${reportJson?.routing_mode === "ai" ? "completed" : "skipped"}`}>
                {reportJson?.routing_mode === "ai" ? "AI 动态编排" : "固定安全流程"}
              </span>
              <Link to={`/tasks/${id}`} className="btn">
                <ArrowLeft size={14} />
                返回任务
              </Link>
              <button type="button" className="btn btn-primary" onClick={() => download("json")}>
                <FileJson size={14} />
                下载 JSON
              </button>
            </>
          )}
        />

        {error && <div className="error-banner mb-4">{error}</div>}

        <section className="metric-grid mb-4">
          <div className="metric">
            <div className="metric-label">Finding 总数</div>
            <strong className="metric-value">{findings.length}</strong>
            <div className="metric-note"><ShieldAlert size={10} className="inline" /> normalized findings</div>
          </div>
          <div className="metric">
            <div className="metric-label">风险组</div>
            <strong className="metric-value">{riskGroups.length}</strong>
            <div className="metric-note"><Layers3 size={10} className="inline" /> deduplicated risks</div>
          </div>
          <div className="metric">
            <div className="metric-label">高危及严重</div>
            <strong className="metric-value">{severity.critical + severity.high}</strong>
            <div className="metric-note">
              critical {severity.critical} · high {severity.high}
            </div>
          </div>
          <div className="metric">
            <div className="metric-label">已执行节点</div>
            <strong className="metric-value">
              {reportJson?.summary_counts?.nodes
                ?? Object.values(reportJson?.node_status || {}).filter(
                  (state) => !["pending", "skipped", "cancelled"].includes(String(state).toLowerCase()),
                ).length}
            </strong>
            <div className="metric-note"><GitBranch size={10} className="inline" /> executed workflow nodes</div>
          </div>
        </section>

        <section className="panel mb-4">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">工作流可视化</h2>
              <p className="panel-kicker">Click the image to inspect · zoom and pan in full screen</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`status-badge ${pngUrl ? "completed" : "skipped"}`}>
                {pngUrl ? "PNG 图片" : "Mermaid 兜底"}
              </span>
              {Object.entries(severity).filter(([, count]) => count > 0).map(([name, count]) => (
                <span key={name} className={`severity ${name}`}>{name} {count}</span>
              ))}
              <button
                type="button"
                className="btn btn-sm"
                onClick={regenerateWorkflow}
                disabled={generatingWorkflow}
              >
                <RefreshCw size={13} className={generatingWorkflow ? "spin" : ""} />
                {generatingWorkflow ? "生成中" : "生成图片"}
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setWorkflowOpen(true)}
                disabled={!pngUrl}
              >
                <Maximize2 size={13} />
                全屏放大
              </button>
              <button type="button" className="btn btn-sm" onClick={() => download("png")}>
                <ImageIcon size={13} />
                PNG
              </button>
            </div>
          </div>
          {pngUrl && (
            <div
              className="workflow-frame workflow-preview"
              role="button"
              tabIndex={0}
              onClick={() => setWorkflowOpen(true)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") setWorkflowOpen(true);
              }}
              title="点击全屏放大"
            >
              <img src={pngUrl} alt="工作流可视化" />
              <span className="workflow-zoom-hint"><Maximize2 size={13} /> 点击全屏放大</span>
            </div>
          )}
          {!pngUrl && mmd && (
            <div className="workflow-frame">
              <div ref={renderRef} className="workflow-canvas p-4" />
            </div>
          )}
          {!pngUrl && !mmd && (
            <div className="empty-state">
              <div>
                <GitBranch size={28} />
                工作流图生成中
              </div>
            </div>
          )}
        </section>

        {workflowOpen && pngUrl && (
          <div
            className="workflow-modal-backdrop"
            role="dialog"
            aria-modal="true"
            aria-label="工作流大图"
            onClick={() => setWorkflowOpen(false)}
          >
            <div className="workflow-modal" onClick={(event) => event.stopPropagation()}>
              <div className="workflow-modal-toolbar">
                <div>
                  <strong>工作流大图</strong>
                  <span>拖动画布查看，使用按钮缩放</span>
                </div>
                <div className="workflow-modal-actions">
                  <button type="button" className="btn btn-sm" onClick={() => setWorkflowZoom((value) => Math.max(0.6, value - 0.2))}>
                    <ZoomOut size={14} />
                  </button>
                  <span>{Math.round(workflowZoom * 100)}%</span>
                  <button type="button" className="btn btn-sm" onClick={() => setWorkflowZoom((value) => Math.min(3, value + 0.2))}>
                    <ZoomIn size={14} />
                  </button>
                  <button type="button" className="btn btn-sm" onClick={() => setWorkflowZoom(1)}>
                    重置
                  </button>
                  <button type="button" className="btn btn-sm" onClick={() => download("png")}>
                    <Download size={13} />
                    PNG
                  </button>
                  <button type="button" className="btn btn-sm" onClick={() => setWorkflowOpen(false)} aria-label="关闭大图">
                    <X size={15} />
                  </button>
                </div>
              </div>
              <div className="workflow-modal-scroll">
                <img
                  src={pngUrl}
                  alt="工作流大图"
                  className="workflow-modal-image"
                  style={{ width: `${workflowZoom * 100}%` }}
                />
              </div>
            </div>
          </div>
        )}

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">完整评估报告</h2>
              <p className="panel-kicker">Detailed findings, evidence and remediation playbooks</p>
            </div>
            <div className="flex items-center gap-2 text-[10px] text-[#74839a]">
              <FileText size={13} />
              HTML report
              <Download size={12} />
            </div>
          </div>
          {html ? (
            <iframe title="完整评估报告" srcDoc={html} className="report-frame" />
          ) : (
            <div className="empty-state">
              <div>
                <FileText size={28} />
                报告生成中
              </div>
            </div>
          )}
        </section>
      </main>
    </AppShell>
  );
}
