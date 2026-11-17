import NodeCard from "./NodeCard";
import { nodeLabels } from "../i18n";


export const NODES = [
  ["auth_gate", "guard"],
  ["recon", "subfinder"],
  ["dns_resolve", "dnsx"],
  ["takeover_check", "subjack"],
  ["http_probe", "httpx"],
  ["port_scan", "nmap"],
  ["credential_session_analysis", "auth analyzer"],
  ["router", "decision"],
  ["web_scan", "zap"],
  ["nuclei_scan", "nuclei"],
  ["js_secret_scan", "gitleaks"],
  ["api_fuzz", "schemathesis"],
  ["k8s_audit", "kubescape"],
  ["server_baseline", "nikto + wapiti"],
  ["active_validation", "safe validators"],
  ["host_vuln_scan", "openvas"],
  ["merge_and_score", "dedup"],
  ["llm_summarize", "optional llm"],
  ["report", "jinja2 + mermaidx"],
];


export default function NodeGrid({ nodeStatus, summaries, details }) {
  return (
    <div className="node-grid">
      {NODES.map(([name, tool]) => (
        <NodeCard
          key={name}
          name={name}
          label={nodeLabels[name] || name}
          tool={tool}
          status={nodeStatus?.[name] || "pending"}
          summary={summaries?.[name]}
          detail={details?.[name]}
        />
      ))}
    </div>
  );
}
