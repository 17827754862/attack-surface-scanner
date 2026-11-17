import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  CircleDashed,
  Clock3,
  Plus,
  ScanLine,
  ServerCog,
  ShieldAlert,
  Target,
} from "lucide-react";
import { Link } from "react-router-dom";
import { api, eventUrl } from "../api";
import AppShell from "../components/AppShell";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import { vulnTypeLabel } from "../i18n";


const RANGES = [
  { value: "7", label: "7D" },
  { value: "30", label: "30D" },
  { value: "90", label: "90D" },
  { value: "all", label: "ALL" },
];

const ENGINE_ORDER = ["zap", "nuclei", "nmap", "httpx", "openvas", "oast"];

const NODE_TOOL = {
  auth_gate: ["guard"],
  recon: ["subfinder"],
  dns_resolve: ["dnsx"],
  takeover_check: ["subjack"],
  http_probe: ["httpx"],
  port_scan: ["nmap"],
  credential_session_analysis: ["auth_analysis"],
  router: ["decision"],
  web_scan: ["zap"],
  nuclei_scan: ["nuclei"],
  js_secret_scan: ["gitleaks"],
  api_fuzz: ["schemathesis"],
  k8s_audit: ["kubescape"],
  server_baseline: ["nikto", "wapiti"],
  active_validation: ["active_validation"],
  host_vuln_scan: ["openvas"],
  merge_and_score: ["dedup"],
  llm_summarize: ["llm"],
  report: ["report"],
};

function formatTime(value) {
  return value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "-";
}

function activityStatus(value) {
  if (value === "on_chain_start") return "RUNNING";
  if (value === "on_chain_end") return "DONE";
  if (value === "on_chain_error") return "ERROR";
  return String(value || "EVENT").toUpperCase();
}


export default function Dashboard() {
  const [assets, setAssets] = useState([]);
  const [tasks, setTasks] = useState([]);
  const [capabilities, setCapabilities] = useState({});
  const [range, setRange] = useState("30");
  const [error, setError] = useState("");
  const [streamEvents, setStreamEvents] = useState([]);
  const streamRef = useRef(null);

  const activeTasks = useMemo(
    () => tasks
      .filter((task) => ["running", "resuming", "queued"].includes(task.status))
      .filter((task) => Date.now() - new Date(task.updated_at || task.created_at).getTime() < 30 * 60 * 1000)
      .slice(0, 3),
    [tasks],
  );

  useEffect(() => {
    Promise.all([
      api("/api/history/assets"),
      api("/api/history/tasks?limit=50"),
      api("/api/capabilities"),
    ]).then(([assetData, taskData, caps]) => {
      setAssets(assetData.items || []);
      setTasks(taskData.items || []);
      setCapabilities(caps || {});
    }).catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    if (!tasks.length) return;
    let active = true;
    api(`/api/tasks/${tasks[0].id}/report?format=json`)
      .then((payload) => {
        if (!active) return;
        const rows = (payload.execution_trace || []).slice(-24).map((entry) => ({
          node: entry.node_name,
          status: entry.status,
          summary: entry.output_summary || entry.error || "",
          target: tasks[0].target,
          time: entry.finished_at || entry.started_at || new Date().toISOString(),
          historical: true,
        }));
        setStreamEvents((current) => current.length ? current : rows);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [tasks]);

  useEffect(() => {
    if (!activeTasks.length) return undefined;
    const sources = activeTasks.map((task) => {
      const source = new EventSource(eventUrl(task.id));
      source.onmessage = (message) => {
        try {
          const event = JSON.parse(message.data);
          if (!event.event && !event.status) return;
          setStreamEvents((current) => [
            ...current.slice(-79),
            {
              node: event.node || event.node_name || "workflow",
              status: event.status || event.event,
              summary: event.summary || event.error || "",
              target: task.target,
              taskId: task.id,
              time: new Date().toISOString(),
            },
          ]);
        } catch {
          // SSE heartbeats are not task events.
        }
      };
      source.onerror = () => source.close();
      return source;
    });
    return () => sources.forEach((source) => source.close());
  }, [activeTasks]);

  useEffect(() => {
    if (!streamRef.current) return;
    streamRef.current.scrollTop = streamRef.current.scrollHeight;
  }, [streamEvents]);

  const metrics = useMemo(() => {
    const findings = assets.reduce((sum, asset) => sum + Number(asset.finding_count || 0), 0);
    const high = assets.reduce(
      (sum, asset) => sum + Number(asset.severity_counts?.critical || 0) + Number(asset.severity_counts?.high || 0),
      0,
    );
    return { assets: assets.length, findings, high, scans: tasks.length };
  }, [assets, tasks]);

  const availableEngines = Object.values(capabilities).filter((item) => item.available).length;
  const topRisks = useMemo(() => {
    const counts = new Map();
    for (const asset of assets) {
      for (const type of asset.risk_types || []) {
        counts.set(type, (counts.get(type) || 0) + 1);
      }
    }
    return [...counts.entries()].sort((left, right) => right[1] - left[1]).slice(0, 6);
  }, [assets]);
  const rangeTasks = useMemo(() => {
    if (range === "all") return tasks;
    const cutoff = Date.now() - Number(range) * 24 * 60 * 60 * 1000;
    return tasks.filter((task) => new Date(task.created_at).getTime() >= cutoff);
  }, [tasks, range]);
  const engineEntries = useMemo(() => {
    const names = [
      ...ENGINE_ORDER,
      ...Object.keys(capabilities).filter((name) => !ENGINE_ORDER.includes(name)),
    ];
    return names.map((name) => ({ name, ...(capabilities[name] || {}) }));
  }, [capabilities]);
  const enginePairs = useMemo(() => {
    const left = engineEntries.slice(0, Math.ceil(engineEntries.length / 2));
    const right = engineEntries.slice(Math.ceil(engineEntries.length / 2));
    const midpoint = Math.ceil(engineEntries.length / 2);
    return Array.from({ length: midpoint }, (_, index) => ({
      left: left[index] || null,
      right: right[index] || null,
    }));
  }, [engineEntries]);
  const latestEvent = streamEvents.at(-1);
  const activeTools = latestEvent
    ? (NODE_TOOL[latestEvent.node] || [String(latestEvent.node || "").toLowerCase()])
    : [];

  return (
    <AppShell>
      <main className="page-shell">
        <PageHeader
          eyebrow="Security overview"
          title="安全态势总览"
          description="资产、风险与扫描编排的实时汇总。数据来自本机扫描历史与执行引擎能力探测。"
          actions={(
            <>
              <div className="range-switch">
                {RANGES.map((item) => (
                  <button
                    key={item.value}
                    type="button"
                    className={range === item.value ? "active" : ""}
                    onClick={() => setRange(item.value)}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
              <span className="live-pill"><span className="status-dot" />Live</span>
              <Link to="/scan" className="btn btn-primary">
                <Plus size={15} />
                新建扫描
              </Link>
            </>
          )}
        />

        {error && <div className="error-banner mb-4">{error}</div>}

        <section className="metric-grid mb-4">
          <div className="metric">
            <div className="metric-head"><Target size={15} /><span>资产总数</span></div>
            <strong className="metric-value">{metrics.assets}</strong>
            <div className="metric-note"><ArrowUpRight size={9} className="inline" /> tracked assets</div>
          </div>
          <div className="metric">
            <div className="metric-head"><ShieldAlert size={15} /><span>风险实例</span></div>
            <strong className="metric-value">{metrics.findings}</strong>
            <div className="metric-note"><Activity size={9} className="inline" /> latest snapshots</div>
          </div>
          <div className="metric">
            <div className="metric-head"><ScanLine size={15} /><span>高危及严重</span></div>
            <strong className="metric-value">{metrics.high}</strong>
            <div className="metric-note"><ArrowDownRight size={9} className="inline" /> critical + high</div>
          </div>
          <div className="metric">
            <div className="metric-head"><Clock3 size={15} /><span>扫描任务</span></div>
            <strong className="metric-value">{metrics.scans}</strong>
            <div className="metric-note"><ServerCog size={9} className="inline" /> {availableEngines} engines ready</div>
          </div>
        </section>

        <div className="dashboard-main">
          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">实时数据流</h2>
                <p className="panel-kicker">
                  {activeTasks.length ? `${activeTasks.length} active task · SSE connected` : "Latest execution trace"}
                </p>
              </div>
              <span className={`live-pill${activeTasks.length ? " active" : ""}`}>
                <span className="status-dot" />
                {activeTasks.length ? "STREAMING" : "IDLE TRACE"}
              </span>
            </div>
            <div className="stream-console" ref={streamRef}>
              {streamEvents.length ? streamEvents.map((event, index) => (
                <div key={`${event.time}-${event.node}-${index}`} className={`stream-row ${activityStatus(event.status).toLowerCase()}`}>
                  <time>{new Date(event.time).toLocaleTimeString("zh-CN", { hour12: false })}</time>
                  <span className="stream-node">{event.node}</span>
                  <span className="stream-target">{event.target}</span>
                  <span className="stream-status">{activityStatus(event.status)}</span>
                  <span className="stream-summary">{event.summary || "节点已更新"}</span>
                </div>
              )) : (
                <div className="stream-empty">
                  <Activity size={22} />
                  <strong>等待扫描事件</strong>
                  <span>启动任务后，节点执行、工具输出和错误信息会实时出现在这里。</span>
                </div>
              )}
            </div>
            <div className="stream-footer">
              <span>执行节点 → 引擎 → 输出摘要</span>
              <span>{streamEvents.length} events buffered</span>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">扫描引擎</h2>
                <p className="panel-kicker">All engines · auto-scroll · two columns</p>
              </div>
              <span className="engine-counter">{availableEngines}/{engineEntries.length} ONLINE</span>
            </div>
            <div className="engine-carousel">
              <div className="engine-track">
                {[...enginePairs, ...enginePairs].map((pair, pairIndex) => (
                  <div className="engine-pair" key={pairIndex}>
                    {[pair.left, pair.right].map((item, side) => {
                      if (!item) return <div key={side} />;
                      const isActive = activeTools.includes(item.name);
                      return (
                        <div key={`${item.name}-${side}`} className={`engine-entry${isActive ? " active" : ""}`}>
                          <span className={`engine-icon${item.available ? " online" : ""}`}>
                            {item.available ? <CheckCircle2 size={12} /> : <CircleDashed size={12} />}
                          </span>
                          <div className="engine-meta">
                            <strong>{item.name}</strong>
                            <span>{item.version?.split("\n")[0] || (item.available ? item.mode || "ready" : "unavailable")}</span>
                          </div>
                          <em>{isActive ? "WORKING" : item.available ? "ONLINE" : "OFFLINE"}</em>
                        </div>
                      );
                    })}
                  </div>
                ))}
              </div>
            </div>
            <div className="stream-footer">
              <span>{latestEvent ? `最近活动：${latestEvent.node}` : "等待引擎活动"}</span>
              <span>hover to pause</span>
            </div>
          </section>
        </div>

        <div className="dashboard-bottom">
          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">最近任务</h2>
                <p className="panel-kicker">Latest assessment runs</p>
              </div>
              <Link to="/history" className="btn btn-sm">查看全部</Link>
            </div>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr><th>目标</th><th>状态</th><th>模式</th><th>风险组</th><th>实例</th><th>时间</th></tr>
                </thead>
                <tbody>
                  {rangeTasks.slice(0, 6).map((task) => (
                    <tr key={task.id}>
                      <td className="mono max-w-[260px] truncate-cell">
                        <Link to={`/tasks/${task.id}`} className="font-medium text-[#e5e5e8] hover:text-[#76a7ff]">
                          {task.target}
                        </Link>
                      </td>
                      <td><StatusBadge status={task.status} /></td>
                      <td className="mono">{task.mode}</td>
                      <td className="mono">{task.risk_group_count}</td>
                      <td className="mono">{task.findings_count}</td>
                      <td className="text-[8px] text-[#686871]">{formatTime(task.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">高频风险</h2>
                <p className="panel-kicker">Across latest asset snapshots</p>
              </div>
            </div>
            <div className="risk-rank">
              {topRisks.map(([type, count], index) => (
                <div key={type} className="risk-rank-row">
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <div className="min-w-0">
                    <strong>{vulnTypeLabel(type)}</strong>
                    <div className="risk-rank-track">
                      <i style={{ width: `${Math.max(8, (count / topRisks[0][1]) * 100)}%` }} />
                    </div>
                  </div>
                  <em>{count}</em>
                </div>
              ))}
              {!topRisks.length && <div className="empty-state">暂无风险趋势数据</div>}
            </div>
          </section>
        </div>
      </main>
    </AppShell>
  );
}
