import { useEffect, useMemo, useState } from "react";
import {
  ArrowUpRight,
  History as HistoryIcon,
  Plus,
  Search,
  ServerCog,
  ShieldAlert,
  Waypoints,
} from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import AppShell from "../components/AppShell";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import { statusLabels, vulnTypeLabel } from "../i18n";


function formatTime(value) {
  return value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "-";
}


export default function History() {
  const [searchParams] = useSearchParams();
  const [assets, setAssets] = useState([]);
  const [tasks, setTasks] = useState([]);
  const [snapshotCount, setSnapshotCount] = useState(0);
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [status, setStatus] = useState("all");
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api("/api/history/assets"), api("/api/history/tasks?limit=50")])
      .then(([assetData, taskData]) => {
        setAssets(assetData.items || []);
        setSnapshotCount(assetData.snapshot_count || 0);
        setTasks(taskData.items || []);
      })
      .catch((err) => setError(err.message));
  }, []);

  const filteredAssets = useMemo(() => {
    const term = query.trim().toLowerCase();
    if (!term) return assets;
    return assets.filter((asset) => asset.target.toLowerCase().includes(term));
  }, [assets, query]);

  const filteredTasks = useMemo(() => {
    const term = query.trim().toLowerCase();
    return tasks.filter((task) => {
      const targetMatches = !term || task.target.toLowerCase().includes(term);
      const statusMatches = status === "all" || task.status === status;
      return targetMatches && statusMatches;
    });
  }, [tasks, query, status]);

  const totals = useMemo(() => {
    const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const asset of assets) {
      for (const [name, value] of Object.entries(asset.severity_counts || {})) {
        severity[name] = (severity[name] || 0) + Number(value || 0);
      }
    }
    return {
      findings: assets.reduce((sum, asset) => sum + Number(asset.finding_count || 0), 0),
      high: (severity.critical || 0) + (severity.high || 0),
    };
  }, [assets]);

  return (
    <AppShell>
      <main className="page-shell">
        <PageHeader
          eyebrow="Asset memory and task ledger"
          title="历史与资产"
          description="按资产回看扫描变化、风险趋势与执行记录，快速定位最近一次评估结果。"
          actions={(
            <Link to="/scan" className="btn btn-primary">
              <Plus size={15} />
              新建扫描
            </Link>
          )}
        />

        {error && <div className="error-banner mb-4">{error}</div>}

        <section className="metric-grid mb-4">
          <div className="metric">
            <div className="metric-label">已记录资产</div>
            <strong className="metric-value">{assets.length}</strong>
            <div className="metric-note"><ServerCog size={10} className="inline" /> unique assets</div>
          </div>
          <div className="metric">
            <div className="metric-label">风险实例</div>
            <strong className="metric-value">{totals.findings}</strong>
            <div className="metric-note"><ShieldAlert size={10} className="inline" /> latest snapshots</div>
          </div>
          <div className="metric">
            <div className="metric-label">高危及严重</div>
            <strong className="metric-value">{totals.high}</strong>
            <div className="metric-note">critical + high</div>
          </div>
          <div className="metric">
            <div className="metric-label">历史快照</div>
            <strong className="metric-value">{snapshotCount}</strong>
            <div className="metric-note"><HistoryIcon size={10} className="inline" /> stored snapshots</div>
          </div>
        </section>

        <div className="two-column mb-4">
          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">资产视图</h2>
                <p className="panel-kicker">Latest assessment per target</p>
              </div>
              <Waypoints size={17} className="text-[#7890af]" />
            </div>
            <div className="border-b border-[#17263b] p-3">
              <div className="toolbar">
                <label className="search-box">
                  <Search size={14} />
                  <input
                    className="input"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="搜索域名、IP 或 URL"
                  />
                </label>
                <select
                  className="select !w-auto min-w-[128px]"
                  value={status}
                  onChange={(event) => setStatus(event.target.value)}
                >
                  <option value="all">全部状态</option>
                  <option value="completed">已完成</option>
                  <option value="partial">部分完成</option>
                  <option value="running">运行中</option>
                  <option value="failed">失败</option>
                  <option value="cancelled">已取消</option>
                </select>
              </div>
            </div>
            <div className="asset-list">
              {filteredAssets.map((asset) => (
                <Link key={asset.asset_key} to={`/tasks/${asset.latest_task_id}`} className="asset-row">
                  <div className="min-w-0">
                    <div className="asset-target">{asset.target}</div>
                    <div className="asset-types">
                      {(asset.risk_types || []).slice(0, 3).map((risk) => (
                        <span key={risk} className="mini-tag">{vulnTypeLabel(risk)}</span>
                      ))}
                      {(asset.risk_types || []).length > 3 && (
                        <span className="mini-tag">+{asset.risk_types.length - 3}</span>
                      )}
                      {!asset.risk_types?.length && <span className="mini-tag">暂无风险类型</span>}
                    </div>
                  </div>
                  <div className="asset-stat">
                    <strong>{asset.scan_count}</strong>
                    <span>扫描次数</span>
                  </div>
                  <div className="asset-stat">
                    <strong>{asset.risk_group_count}</strong>
                    <span>风险组</span>
                  </div>
                  <div className="asset-stat">
                    <strong className={asset.finding_delta > 0 ? "!text-[#d33d4a]" : "!text-[#07856e]"}>
                      {asset.finding_delta > 0 ? "+" : ""}{asset.finding_delta}
                    </strong>
                    <span>实例变化</span>
                  </div>
                  <div className="text-right text-[9px] text-[#8b98ab]">
                    <div>{formatTime(asset.latest_scan_at)}</div>
                    <span className="mt-2 inline-flex items-center gap-1 text-[#0a59f7]">
                      打开任务 <ArrowUpRight size={10} />
                    </span>
                  </div>
                </Link>
              ))}
              {!filteredAssets.length && (
                <div className="empty-state">
                  <div>
                    <Search size={25} />
                    没有匹配的资产
                  </div>
                </div>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">近期任务</h2>
                <p className="panel-kicker">Latest 8 runs</p>
              </div>
              <HistoryIcon size={17} className="text-[#7890af]" />
            </div>
            <div className="panel-body">
              <div className="timeline">
                {tasks.slice(0, 8).map((task) => (
                  <Link key={task.id} to={`/tasks/${task.id}`} className="timeline-item">
                    <span className={`timeline-dot ${task.status}`} />
                    <div className="min-w-0">
                      <div className="timeline-target">{task.target}</div>
                      <div className="timeline-meta">
                        <StatusBadge status={task.status} />
                        <span>{task.findings_count} findings</span>
                      </div>
                      <div className="mt-1 text-[9px] text-[#94a0b3]">{formatTime(task.created_at)}</div>
                    </div>
                  </Link>
                ))}
                {!tasks.length && <div className="empty-state">暂无任务记录</div>}
              </div>
            </div>
          </section>
        </div>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2 className="panel-title">任务记录</h2>
              <p className="panel-kicker">Assessment task ledger</p>
            </div>
            <span className="text-[10px] text-[#94a0b3]">{filteredTasks.length} records</span>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>目标 / Target</th>
                  <th>状态 / Status</th>
                  <th>模式 / Mode</th>
                  <th>风险组</th>
                  <th>实例</th>
                  <th>执行组合</th>
                  <th>创建时间</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {filteredTasks.map((task) => (
                  <tr key={task.id}>
                    <td className="mono max-w-[320px] truncate-cell">
                      <Link to={`/tasks/${task.id}`} className="font-semibold text-[#0a59f7] hover:underline">
                        {task.target}
                      </Link>
                    </td>
                    <td><StatusBadge status={task.status} label={statusLabels[task.status] || task.status} /></td>
                    <td className="mono">{task.mode}</td>
                    <td className="mono">{task.risk_group_count}</td>
                    <td className="mono">{task.findings_count}</td>
                    <td className="mono">{task.tool_profile}</td>
                    <td className="text-[9px] text-[#8090a6]">{formatTime(task.created_at)}</td>
                    <td>
                      <Link className="icon-button !h-7 !w-7" to={`/tasks/${task.id}`} aria-label="打开任务">
                        <ArrowUpRight size={12} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </AppShell>
  );
}
