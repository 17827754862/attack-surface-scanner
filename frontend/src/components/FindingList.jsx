import { FileSearch } from "lucide-react";
import { severityLabels, vulnTypeLabel } from "../i18n";


export default function FindingList({ findings }) {
  if (!findings?.length) {
    return (
      <div className="empty-state">
        <div>
          <FileSearch size={28} />
          当前任务暂无 Finding
        </div>
      </div>
    );
  }

  return (
    <div className="finding-list">
      {findings.map((finding) => (
        <details
          key={finding.fingerprint || `${finding.source}-${finding.url}-${finding.vuln_type}`}
          className="finding-row"
        >
          <summary>
            <span className={`severity ${finding.severity || "info"}`}>
              {severityLabels[finding.severity] || finding.severity || "信息"}
            </span>
            <div>
              <div className="finding-title">{vulnTypeLabel(finding.vuln_type)}</div>
              <div className="finding-host">
                {finding.host || "-"}{finding.port ? `:${finding.port}` : ""} · {finding.url || "无 URL"}
              </div>
            </div>
            <div className="confidence">
              <strong>{finding.confidence ?? 0}</strong>
              <span>confidence</span>
            </div>
            <div className="text-right text-[9px] text-[#697892]">{finding.source}</div>
          </summary>
          <pre className="evidence-block">
            {JSON.stringify({
              evidence_hash: finding.evidence_hash,
              also_reported_by: finding.also_reported_by,
              evidence: finding.evidence,
            }, null, 2)}
          </pre>
        </details>
      ))}
    </div>
  );
}
