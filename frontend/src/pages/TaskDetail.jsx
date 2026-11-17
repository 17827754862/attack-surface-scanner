import { useEffect, useMemo, useState } from "react";
import {
  BrainCircuit,
  Download,
  ExternalLink,
  FileJson,
  FileText,
  Gauge,
  History,
  Image as ImageIcon,
  ListChecks,
  RefreshCw,
  RotateCcw,
  ScanLine,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { api, downloadFile, eventUrl } from "../api";
import AppShell from "../components/AppShell";
import DataFlow from "../components/DataFlow";
import FindingList from "../components/FindingList";
import PageHeader from "../components/PageHeader";
import RiskGroupList from "../components/RiskGroupList";
import StatusBadge from "../components/StatusBadge";
import TraceView from "../components/TraceView";
import { statusLabels } from "../i18n";


const TERMINAL_STATUSES = ["done", "completed", "partial", "failed", "blocked", "cancelled"];
const ACTIVE_STATUSES = ["running", "resuming", "queued"];


function summaryText(value) {
  if (!value) return "";
  if (typeof value === "string") return value;
  return value.text || value.summary_zh || value.summary_en || "";
}


export default function TaskDetail() {
  const { id } = useParams();
  const [task, setTask] = useState(null);
  const [findings, setFindings] = useState([]);
  const [events, setEvents] = useState([]);
  const [executionTrace, setExecutionTrace] = useState([]);
  const [tab, setTab] = useState("risks");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    let timer = null;
    async function load() {
      try {
        const data = await api(`/api/tasks/${id}`);
        if (!active) return;
        setTask(data);
        if (TERMINAL_STATUSES.includes(data.status)) {
          const [found, report] = await Promise.all([
            api(`/api/tasks/${id}/findings`).catch(() => ({ findings: [] })),
            api(`/api/tasks/${id}/report?format=json`).catch(() => ({ execution_trace: [] })),
          ]);
          if (active) {
            setFindings(found.findings || []);
            setExecutionTrace(report.execution_trace || []);
          }
        } else {
          timer = setTimeout(load, 2000);
        }
      } catch (err) {
        if (active) setError(err.message);
      }
    }
    load();
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [id]);

  useEffect(() => {
    const source = new EventSource(eventUrl(id));
    source.onmessage = (event) => {
      try {
        setEvents((prev) => [...prev.slice(-119), JSON.parse(event.data)]);
      } catch {
        // Heartbeats and non-JSON events do not alter task state.
      }
    };
    source.onerror = () => source.close();
    return () => source.close();
  }, [id]);

  const summaries = useMemo(() => {
    const value = {};
    for (const entry of executionTrace) {
      if (entry.node_name) value[entry.node_name] = entry.output_summary || "";
    }
    for (const event of events) {
      if (event.event === "on_chain_end" && event.summary !== undefined) {
        value[event.node] = event.summary;
      }
    }
    return value;
  }, [events, executionTrace]);

  const details = useMemo(() => {
    const value = {};
    for (const entry of executionTrace) {
      if (entry.node_name) value[entry.node_name] = entry.error || entry.output_summary || "";
    }
    for (const event of events) {
      if (event.error) value[event.node] = event.error;
    }
    return value;
  }, [events, executionTrace]);

  const liveStatus = useMemo(() => {
    const value = {};
    for (const event of events) {
      if (event.event === "on_chain_start") value[event.node] = "running";
      if (event.event === "on_chain_end") value[event.node] = event.status || "done";
      if (event.event === "on_chain_error") value[event.node] = "failed";
    }
    return value;
  }, [events]);

  const nodeStatus = { ...(task?.node_status || {}), ...liveStatus };
  const nodeValues = Object.values(nodeStatus);
  const completedNodes = nodeValues.filter((value) => ["done", "completed"].includes(value)).length;
  const failedNodes = nodeValues.filter((value) => value === "failed").length;
  const totalNodes = nodeValues.length || 19;
  const completion = Math.round((completedNodes / totalNodes) * 100);
  const severity = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const group of task?.risk_groups || []) {
      const key = group.severity || "info";
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, [task?.risk_groups]);
  const aiText = summaryText(task?.llm_summary);
  const isActive = task && ACTIVE_STATUSES.includes(task.status);
  const routingMode = task?.routing_mode || "auto";
  const routingLabel = routingMode === "ai"
    ? "AI 动态编排"
    : routingMode === "fixed"
      ? "固定安全流程"
      : "智能检测中";

  async function cancel() {
    try {
      const data = await api(`/api/tasks/${id}/cancel`, { method: "POST" });
      setTask(data);
    } catch (err) {
      setError(err.message);
    }
  }

  async function resume() {
    try {
      const data = await api(`/api/tasks/${id}/resume`, { method: "POST" });
      setTask(data);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }

  async function download(kind) {
    try {
      if (kind === "png") {
        await downloadFile(`/api/tasks/${id}/workflow.png`, `workflow-${id}.png`);
      } else if (kind === "mmd") {
        await downloadFile(`/api/tasks/${id}/graph.mmd`, `workflow-${id}.mmd`);
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
          eyebrow="Assessment execution"
          title={task?.target || "正在加载任务"}
          description={`task_id: ${id} · ${task?.mode || "-"} mode · ${task?.tool_profile || "-"} · ${routingLabel}`}
          actions={task && (
            <>
              <StatusBadge status={task.status} label={statusLabels[task.status] || task.status} />
              {isActive && (
                <button type="button" className="btn btn-danger" onClick={cancel}>
                  <XCircle size={14} />
                  取消任务
                </button>
              )}
              {["failed", "cancelled"].includes(task.status) && (
                <button type="button" className="btn" onClick={resume}>
                  <RotateCcw size={14} />
                  从断点恢复
                </button>
              )}
              <Link to="/scan" className="btn">
                <ScanLine size={14} />
                新建扫描
              </Link>
              <Link to={`/tasks/${id}/report`} className="btn btn-primary">
                <FileText size={14} />
                查看报告
                <ExternalLink size={12} />
              </Link>
            </>
          )}
        />

        {error && <div className="error-banner mb-4">{error}</div>}

        {task && (
          <>
            <section className="metric-grid mb-4">
              <div className="metric">
                <div className="metric-label">Finding 实例</div>
                <strong className="metric-value">{task.findings_count || findings.length || 0}</strong>
                <div className="metric-note"><ShieldAlert size={10} className="inline" /> normalized records</div>
              </div>
              <div className="metric">
                <div className="metric-label">风险组</div>
                <strong className="metric-value">{task.risk_groups?.length || 0}</strong>
                <div className="metric-note">
                  高危 {severity.critical + severity.high} · 中危 {severity.medium}
                </div>
              </div>
              <div className="metric">
                <div className="metric-label">节点完成度</div>
                <strong className="metric-value">{completion}%</strong>
                <div className="progress-track mt-2">
                  <div className="progress-value" style={{ width: `${completion}%` }} />
                </div>
                <div className="metric-note mt-2">{completedNodes}/{totalNodes} nodes · {failedNodes} failed</div>
              </div>
              <div className="metric">
                <div className="metric-label">验证级别</div>
                <strong className="metric-value">{task.validation_level}</strong>
                <div className="metric-note">主动验证策略</div>
              </div>
            </section>

            {task.blocked_targets?.length > 0 && (
              <section className="panel mb-4 border-[#efd09d]">
                <div className="panel-header !border-[#3b2c16] !bg-[#100c05]">
                  <div>
                    <h2 className="panel-title !text-[#f4d7a7]">已拦截越界目标</h2>
                    <p className="panel-kicker">Scope guard blocked out-of-scope destinations</p>
                  </div>
                  <ShieldAlert size={16} className="text-[#b66a08]" />
                </div>
                <div className="grid gap-1 p-4 font-mono text-[9px] text-[#b29466]">
                  {task.blocked_targets.map((target) => <span key={target}>{target}</span>)}
                </div>
              </section>
            )}

            {task.memory_context?.scan_count > 0 && (
              <div className="notice-banner mb-4 flex flex-wrap items-center gap-4">
                <History size={15} />
                <span>历史扫描 {task.memory_context.scan_count} 次</span>
                <span>新增风险 {(task.memory_context.new_risk_types || []).length}</span>
                <span>已消失风险 {(task.memory_context.resolved_risk_types || []).length}</span>
                {(task.memory_context.new_risk_types || []).length > 0 && (
                  <span className="text-[#60708b]">
                    {(task.memory_context.new_risk_types || []).slice(0, 4).join(" · ")}
                  </span>
                )}
              </div>
            )}

            <section className="panel mb-4">
              <div className="panel-header">
                <div>
                  <h2 className="panel-title">执行工作流</h2>
                  <p className="panel-kicker">Actual tool sequence · tools appear as their data arrives</p>
                </div>
                <div className="flex items-center gap-2 text-[10px] text-[#718199]">
                  <RefreshCw size={12} className={isActive ? "spin" : ""} />
                  {isActive ? "SSE 实时更新" : "数据流已结束"}
                </div>
              </div>
              <div className="panel-body">
                <DataFlow
                  nodeStatus={nodeStatus}
                  summaries={summaries}
                  details={details}
                  events={events}
                  executionTrace={executionTrace}
                  decisions={task.scan_decisions || []}
                  routingMode={routingMode}
                />
              </div>
            </section>

            <div className="detail-layout">
              <section className="panel">
                <div className="tabs">
                  <button
                    type="button"
                    className={`tab${tab === "risks" ? " active" : ""}`}
                    onClick={() => setTab("risks")}
                  >
                    风险组 / Risk groups
                    <span className="ml-2 bg-[#102038] px-1.5 py-0.5 text-[8px] text-[#6d83a1]">
                      {task.risk_groups?.length || 0}
                    </span>
                  </button>
                  <button
                    type="button"
                    className={`tab${tab === "findings" ? " active" : ""}`}
                    onClick={() => setTab("findings")}
                  >
                    Finding 实例
                    <span className="ml-2 bg-[#102038] px-1.5 py-0.5 text-[8px] text-[#6d83a1]">
                      {task.findings_count || 0}
                    </span>
                  </button>
                </div>
                {tab === "risks" ? (
                  <RiskGroupList groups={task.risk_groups || []} />
                ) : (
                  <FindingList findings={findings} />
                )}
              </section>

              <aside className="side-stack">
                <section className="panel">
                  <div className="panel-header">
                    <div>
                      <h2 className="panel-title">任务概览</h2>
                      <p className="panel-kicker">Execution context</p>
                    </div>
                    <Gauge size={17} className="text-[#7890af]" />
                  </div>
                  <div className="panel-body">
                    <div className="summary-list">
                      <div className="summary-row">
                        <span className="summary-label">扫描模式</span>
                        <span className="summary-value">{task.mode}</span>
                      </div>
                      <div className="summary-row">
                        <span className="summary-label">登录态</span>
                        <span className={`summary-value ${task.auth_ref && task.auth_ref !== "none" ? "text-[#7db3ff]" : ""}`}>
                          {task.auth_ref === "custom" ? "临时登录账号" : task.auth_ref || "none"}
                        </span>
                      </div>
                      <div className="summary-row">
                        <span className="summary-label">工具组合</span>
                        <span className="summary-value">{task.tool_profile}</span>
                      </div>
                      <div className="summary-row">
                        <span className="summary-label">编排方式</span>
                        <span className="summary-value">
                          {routingLabel}
                        </span>
                      </div>
                      <div className="summary-row">
                        <span className="summary-label">验证级别</span>
                        <span className="summary-value">{task.validation_level}</span>
                      </div>
                      <div className="summary-row">
                        <span className="summary-label">OAST</span>
                        <span className="summary-value">{task.oast_enabled ? "ENABLED" : "DISABLED"}</span>
                      </div>
                    </div>
                  </div>
                </section>

                <section className="panel">
                  <div className="panel-header">
                    <div>
                      <h2 className="panel-title">实时事件</h2>
                      <p className="panel-kicker">Workflow event stream</p>
                    </div>
                    <span className="status-dot text-[#13a181]" />
                  </div>
                  <div className="p-3">
                    <TraceView events={events.length ? events : executionTrace.map((entry) => ({
                      node: entry.node_name,
                      event: entry.status,
                      summary: entry.output_summary,
                      error: entry.error,
                    }))} />
                  </div>
                </section>

                <section className="panel">
                  <div className="panel-header">
                    <div>
                      <h2 className="panel-title">交付文件</h2>
                      <p className="panel-kicker">Evidence and report exports</p>
                    </div>
                    <Download size={17} className="text-[#7890af]" />
                  </div>
                  <div className="grid gap-2 p-3">
                    <button type="button" className="btn justify-start" onClick={() => download("png")}>
                      <ImageIcon size={14} />
                      下载工作流 PNG
                    </button>
                    <button type="button" className="btn justify-start" onClick={() => download("mmd")}>
                      <ListChecks size={14} />
                      下载 Mermaid 源
                    </button>
                    <button type="button" className="btn justify-start" onClick={() => download("json")}>
                      <FileJson size={14} />
                      下载 JSON 报告
                    </button>
                  </div>
                </section>
              </aside>
            </div>

            {aiText && (
              <section className="panel mt-4 border-[#1d3c68]">
                <div className="panel-header !bg-[#071426]">
                  <div>
                    <h2 className="panel-title !text-[#9ebff4]">AI 辅助研判</h2>
                    <p className="panel-kicker">Narrative enhancement after deterministic merge</p>
                  </div>
                  <BrainCircuit size={17} className="text-[#0a59f7]" />
                </div>
                <div className="whitespace-pre-wrap p-5 text-[10px] leading-7 text-[#8299b8]">{aiText}</div>
              </section>
            )}
          </>
        )}

        {!task && !error && <div className="panel empty-state">正在加载任务状态...</div>}
      </main>
    </AppShell>
  );
}
