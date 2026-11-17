import {
  BrainCircuit,
  Check,
  ChevronRight,
  CircleDashed,
  FileText,
  LoaderCircle,
  Route,
  ShieldCheck,
  TriangleAlert,
  Wrench,
  X,
} from "lucide-react";
import { nodeLabels, statusLabels } from "../i18n";
import { NODES } from "./NodeGrid";


const TOOL_BY_NODE = Object.fromEntries(NODES);
const CONTROL_NODES = new Set([
  "auth_gate",
  "router",
  "merge_and_score",
  "llm_summarize",
  "report",
]);
function iconFor(node, status) {
  if (node === "router") return BrainCircuit;
  if (["failed", "blocked"].includes(status)) return TriangleAlert;
  if (["done", "completed"].includes(status)) return Check;
  if (["running", "resuming"].includes(status)) return LoaderCircle;
  if (status === "cancelled") return X;
  if (status === "skipped") return CircleDashed;
  if (node === "auth_gate") return ShieldCheck;
  if (node === "report") return FileText;
  return Wrench;
}


const STATUS_PRIORITY = {
  pending: 0,
  running: 1,
  resuming: 1,
  skipped: 2,
  done: 3,
  completed: 3,
  failed: 4,
  blocked: 4,
  cancelled: 4,
};


function addOrUpdate(items, entry) {
  const existing = items.find((item) => item.node === entry.node);
  if (!existing) {
    items.push({
      ...entry,
      status: entry.status || "pending",
      summary: entry.summary || "",
      error: entry.error || "",
    });
    return;
  }
  existing.tool = entry.tool || existing.tool;
  if ((STATUS_PRIORITY[entry.status] ?? 0) >= (STATUS_PRIORITY[existing.status] ?? 0)) {
    existing.status = entry.status || existing.status;
  }
  if (entry.summary) existing.summary = entry.summary;
  if (entry.error) existing.error = entry.error;
}


function buildTimeline(events, trace, nodeStatus) {
  const items = [];
  if (trace?.length) {
    for (const entry of trace) {
      addOrUpdate(items, {
        node: entry.node_name,
        tool: TOOL_BY_NODE[entry.node_name],
        status: entry.status || "done",
        summary: entry.output_summary || "",
        error: entry.error || "",
      });
    }
  } else {
    for (const [node] of NODES) {
      const status = nodeStatus?.[node];
      if (!status || status === "pending") continue;
      items.push({
        node,
        tool: TOOL_BY_NODE[node],
        status,
        summary: "",
        error: "",
      });
    }
  }
  for (const event of events || []) {
    if (event.event === "on_chain_start") {
      addOrUpdate(items, {
        node: event.node,
        tool: event.tool || TOOL_BY_NODE[event.node],
        status: "running",
        summary: "",
        error: "",
      });
    }
    if (event.event === "on_chain_end" || event.event === "on_chain_error") {
      addOrUpdate(items, {
        node: event.node,
        tool: event.tool || TOOL_BY_NODE[event.node],
        status: event.event === "on_chain_error" ? "failed" : (event.status || "done"),
        summary: event.summary || "",
        error: event.error || "",
      });
    }
  }
  if (!items.length) {
    for (const [node, status] of Object.entries(nodeStatus || {})) {
      if (status && status !== "pending") {
        items.push({
          node,
          tool: TOOL_BY_NODE[node],
          status,
          summary: "",
          error: "",
        });
      }
    }
  }
  return items;
}


function decisionForNode(decisions, node) {
  return [...(decisions || [])].reverse().find((item) => item.node === node);
}


export default function DataFlow({
  nodeStatus,
  summaries,
  details,
  events,
  executionTrace,
  decisions,
  routingMode,
}) {
  const timeline = buildTimeline(events, executionTrace, nodeStatus);
  const visible = timeline.filter((item) => {
    if (!item.node) return false;
    if (item.status === "pending") return false;
    if (item.status === "skipped") return false;
    return true;
  });
  const usedTools = [...new Set(
    visible
      .filter((item) => !CONTROL_NODES.has(item.node))
      .map((item) => item.tool)
      .filter(Boolean),
  )];

  if (!visible.length) {
    return (
      <div className="data-flow-empty" role="status" aria-live="polite">
        <div className="data-flow-wait-animation" aria-hidden="true">
          <span className="data-flow-wait-ring" />
          <span className="data-flow-wait-ring" />
          <span className="data-flow-wait-ring" />
          <CircleDashed size={34} className="data-flow-wait-icon" />
        </div>
        <strong>等待第一个扫描器返回数据</strong>
      </div>
    );
  }

  return (
    <div className="data-flow-wrap">
      <div className="data-flow-toolbar">
        <span className={`routing-mode ${routingMode === "ai" ? "ai" : ""}`}>
          {routingMode === "ai" ? <BrainCircuit size={14} /> : <Route size={14} />}
          {routingMode === "ai"
            ? "AI 动态编排"
            : routingMode === "fixed"
              ? "固定安全流程"
              : "正在检测模型配置"}
        </span>
        <span>已执行工具 {usedTools.length} 个</span>
      </div>

      <div className="data-flow" aria-label="实际扫描数据流">
        {visible.map((item, index) => {
          const Icon = iconFor(item.node, item.status);
          const decision = decisionForNode(decisions, item.node);
          const summary = item.summary || summaries?.[item.node] || "";
          const error = item.error || details?.[item.node] || "";
          const isRouter = item.node === "router";
          return (
            <div className="data-flow-segment" key={item.node}>
              <article className={`flow-node ${item.status}${isRouter ? " router" : ""}`}>
                <div className="flow-node-top">
                  <span className="flow-step">{String(index + 1).padStart(2, "0")}</span>
                  <span className={`flow-status ${item.status}`}>
                    <Icon size={15} className={["running", "resuming"].includes(item.status) ? "spin" : ""} />
                    {isRouter && routingMode === "ai"
                      ? "智能决策"
                      : statusLabels[item.status] || item.status}
                  </span>
                </div>
                <h3>{isRouter ? "动态扫描调度" : nodeLabels[item.node] || item.node}</h3>
                <div className="flow-tool">
                  <Wrench size={13} />
                  {isRouter
                    ? (routingMode === "ai" ? "LLM router" : "rule router")
                    : (item.tool || "internal")}
                </div>
                {(summary || error) && <p>{summary || error}</p>}
                {decision && (
                  <div className={`flow-decision ${decision.source}`}>
                    {decision.source === "ai" ? <BrainCircuit size={13} /> : <Route size={13} />}
                    <span>
                      {decision.source === "ai" ? "AI 选择" : "固定顺序"}
                      {decision.confidence ? ` · ${decision.confidence}%` : ""}
                    </span>
                  </div>
                )}
              </article>
              {index < visible.length - 1 && (
                <div className="flow-connector" aria-hidden="true">
                  <span>data</span>
                  <ChevronRight size={22} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
