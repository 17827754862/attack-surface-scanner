import { DatabaseZap, ShieldCheck } from "lucide-react";
import { severityLabels, vulnTypeLabel } from "../i18n";


function severityLabel(severity) {
  return severityLabels[severity] || severity || "信息";
}


export default function RiskGroupList({ groups }) {
  if (!groups?.length) {
    return (
      <div className="empty-state">
        <div>
          <ShieldCheck size={28} />
          当前范围暂无风险组
        </div>
      </div>
    );
  }

  return (
    <div className="risk-list">
      {groups.map((group) => (
        <details key={group.key || group.vuln_type} className="risk-row">
          <summary>
            <span className={`severity ${group.severity || "info"}`}>
              {severityLabel(group.severity)}
            </span>
            <div>
              <div className="risk-main-title">
                {group.title_zh || vulnTypeLabel(group.vuln_type)}
              </div>
              <div className="risk-main-subtitle">
                {group.title_en || group.vuln_type} · {group.sources?.join(" + ") || "local"}
              </div>
            </div>
            <div className="risk-count">
              <strong>{group.instance_count || 0}</strong>
              <span>实例</span>
            </div>
            <div className="risk-count">
              <strong>{group.affected_url_count || 0}</strong>
              <span>URL</span>
            </div>
          </summary>
          <div className="risk-detail">
            {group.description_zh && (
              <section>
                <h4>风险解读 / Interpretation</h4>
                <p>{group.description_zh}</p>
                {group.description_en && <p className="mt-2 text-[#94a0b3]">{group.description_en}</p>}
              </section>
            )}
            {group.impact_zh && (
              <section>
                <h4>潜在影响 / Impact</h4>
                <p>{group.impact_zh}</p>
              </section>
            )}
            {group.reproduction_steps_zh?.length > 0 && (
              <section>
                <h4>复现验证 / Verification</h4>
                <ol>
                  {group.reproduction_steps_zh.map((step) => <li key={step}>{step}</li>)}
                </ol>
              </section>
            )}
            {group.false_positive_checks_zh?.length > 0 && (
              <section>
                <h4>误报检查 / False-positive checks</h4>
                <ul>
                  {group.false_positive_checks_zh.map((step) => <li key={step}>{step}</li>)}
                </ul>
              </section>
            )}
            {group.remediation_zh?.length > 0 && (
              <section>
                <h4>修复建议 / Remediation</h4>
                <ul>
                  {group.remediation_zh.map((step) => <li key={step}>{step}</li>)}
                </ul>
              </section>
            )}
            {group.affected_urls?.length > 0 && (
              <section className="col-span-2">
                <h4>受影响 URL / Affected URLs</h4>
                <div className="risk-urls">
                  {group.affected_urls.map((url) => <span key={url}>{url}</span>)}
                </div>
              </section>
            )}
            <div className="col-span-2 flex flex-wrap gap-2">
              <span className="mini-tag">
                <DatabaseZap size={9} className="mr-1" />
                {group.analysis_source === "ai" ? "AI 辅助研判" : "确定性规则"}
              </span>
              {group.playbook && <span className="mini-tag">{group.playbook}</span>}
            </div>
          </div>
        </details>
      ))}
    </div>
  );
}
