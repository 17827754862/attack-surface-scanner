import {
  Ban,
  Check,
  CircleDashed,
  LoaderCircle,
  TriangleAlert,
} from "lucide-react";
import { statusLabels } from "../i18n";


function StatusIcon({ status }) {
  if (["completed", "done"].includes(status)) return <Check size={11} strokeWidth={2.5} />;
  if (["running", "resuming"].includes(status)) {
    return <LoaderCircle size={11} strokeWidth={2.2} className="spin" />;
  }
  if (status === "failed") return <TriangleAlert size={11} />;
  if (["cancelled", "skipped"].includes(status)) return <Ban size={11} />;
  return <CircleDashed size={11} />;
}


export default function StatusBadge({ status = "pending", label }) {
  return (
    <span className={`status-badge ${status}`}>
      <StatusIcon status={status} />
      {label || statusLabels[status] || status}
    </span>
  );
}
