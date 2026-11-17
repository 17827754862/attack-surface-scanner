export const nodeLabels = {
  auth_gate: "授权门禁",
  recon: "资产发现",
  dns_resolve: "DNS 解析",
  takeover_check: "子域接管检查",
  http_probe: "HTTP 探测",
  port_scan: "端口扫描",
  credential_session_analysis: "认证与会话分析",
  router: "条件路由",
  web_scan: "Web 动态扫描",
  nuclei_scan: "模板漏洞扫描",
  js_secret_scan: "前端密钥扫描",
  api_fuzz: "API 契约检查",
  k8s_audit: "K8s 配置审计",
  server_baseline: "服务器基线检查",
  active_validation: "通用主动验证",
  host_vuln_scan: "主机漏洞扫描",
  merge_and_score: "归一化与评分",
  llm_summarize: "AI 解读",
  report: "报告生成",
};

export const statusLabels = {
  pending: "等待 / Pending",
  queued: "排队 / Queued",
  running: "运行中 / Running",
  resuming: "恢复中 / Resuming",
  done: "完成 / Done",
  completed: "已完成 / Completed",
  partial: "部分完成 / Partial",
  failed: "失败 / Failed",
  blocked: "已拦截 / Blocked",
  cancelled: "已取消 / Cancelled",
  skipped: "跳过 / Skipped",
};

export const toolLabels = {
  subfinder: "被动子域发现 / Passive Subdomain Discovery",
  dnsx: "DNS 解析 / DNS Resolution",
  httpx: "HTTP 指纹 / HTTP Probing",
  nmap: "端口与服务识别 / Port and Service Discovery",
  nuclei: "模板漏洞扫描 / Template-based Scanning",
  zap: "Web 主动扫描 / Active Web Scanning",
  openvas: "主机漏洞扫描 / Host Vulnerability Scanning",
  schemathesis: "API 契约检查 / API Contract Testing",
  kubescape: "K8s 基线检查 / Kubernetes Baseline",
  subjack: "接管检查 / Takeover Check",
  gitleaks: "密钥扫描 / Secret Scanning",
  nikto: "服务器配置检查 / Server Configuration Checks",
  wapiti: "Web 参数扫描 / Web Parameter Scanning",
  "auth-analysis": "认证与会话分析 / Authentication and Session Analysis",
  "safe-validators": "通用主动验证 / Safe Active Validation",
  oast: "回调验证服务 / OAST Callback Service",
};

export const vulnTypeLabels = {
  default_credentials: "默认或弱口令 / Default Credentials",
  sensitive_file_exposure: "敏感文件暴露 / Sensitive File Exposure",
  missing_security_headers: "缺少安全响应头 / Missing Security Headers",
  cleartext_login: "明文登录 / Cleartext Login",
  known_cve: "已知 CVE / Known CVE",
  kubernetes_misconfiguration: "K8s 配置风险 / Kubernetes Misconfiguration",
  sql_injection: "SQL 注入 / SQL Injection",
  cross_site_scripting: "跨站脚本 / XSS",
  file_inclusion: "文件包含 / File Inclusion",
  file_upload: "文件上传风险 / File Upload",
  command_injection: "命令注入 / Command Injection",
  weak_session_id: "弱会话标识 / Weak Session ID",
  session_fixation: "会话固定 / Session Fixation",
  brute_force: "登录限速缺失 / Missing Login Throttling",
  ssrf: "服务端请求伪造 / SSRF",
  xxe: "XML 外部实体注入 / XXE",
  csrf: "跨站请求伪造 / CSRF",
  cookie_security: "Cookie 安全属性不足 / Insecure Cookie",
  information_disclosure: "信息泄露 / Information Disclosure",
  subdomain_takeover: "子域接管 / Subdomain Takeover",
  open_port: "开放服务端口 / Open Service Port",
  api_contract_failure: "API 契约异常 / API Contract Failure",
};

export const severityLabels = {
  critical: "严重 / Critical",
  high: "高危 / High",
  medium: "中危 / Medium",
  low: "低危 / Low",
  info: "信息 / Info",
};

export function nodeLabel(name) {
  return nodeLabels[name] ? `${nodeLabels[name]} / ${name}` : name;
}

export function vulnTypeLabel(name) {
  return vulnTypeLabels[name] || name?.replaceAll("_", " ") || "Unknown";
}
