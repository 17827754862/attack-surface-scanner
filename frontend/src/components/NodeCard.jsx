import {
  Ban,
  Check,
  CircleDashed,
  LoaderCircle,
  TriangleAlert,
  X,
} from "lucide-react";
import { statusLabels } from "../i18n";


function StatusIcon({ status }) {
  if (["done", "completed"].includes(status)) return <Check size={11} strokeWidth={2.5} />;
  if (["running", "resuming"].includes(status)) {
    return <LoaderCircle size={11} className="spin" />;
  }
  if (["failed", "blocked"].includes(status)) return <TriangleAlert size={11} />;
  if (status === "cancelled") return <X size={11} />;
  if (status === "skipped") return <Ban size={11} />;
  return <CircleDashed size={11} />;
}


export default function NodeCard({ name, label, status = "pending", summary, detail, tool }) {
  const description = summary || detail || statusLabels[status] || status;
  return (
    <article className={`node-card ${status}`} title={`${name} · ${description}`}>
      <div className="node-card-head">
        <span className="node-label">{label}</span>
        <span className={`node-status-line ${status} !mt-0`}>
          <StatusIcon status={status} />
        </span>
      </div>
      <div className="node-tool">{name} / {tool}</div>
      <div className="node-summary">{description}</div>
      <div className={`node-status-line ${status}`}>
        <StatusIcon status={status} />
        {statusLabels[status] || status}
      </div>
    </article>
  );
}
