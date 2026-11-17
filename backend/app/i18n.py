from __future__ import annotations


SEVERITY_LABELS = {
    "critical": ("严重", "Critical"),
    "high": ("高危", "High"),
    "medium": ("中危", "Medium"),
    "low": ("低危", "Low"),
    "info": ("信息", "Info"),
}

STATUS_LABELS = {
    "pending": ("等待", "Pending"),
    "queued": ("排队", "Queued"),
    "running": ("运行中", "Running"),
    "resuming": ("恢复中", "Resuming"),
    "done": ("完成", "Done"),
    "completed": ("已完成", "Completed"),
    "partial": ("部分完成", "Partial"),
    "failed": ("失败", "Failed"),
    "blocked": ("已拦截", "Blocked"),
    "cancelled": ("已取消", "Cancelled"),
    "skipped": ("已跳过", "Skipped"),
}

VULN_TYPE_LABELS = {
    "default_credentials": ("默认或弱口令", "Default Credentials"),
    "sensitive_file_exposure": ("敏感文件暴露", "Sensitive File Exposure"),
    "missing_security_headers": ("缺少安全响应头", "Missing Security Headers"),
    "cleartext_login": ("明文登录传输", "Cleartext Login"),
    "known_cve": ("已知 CVE", "Known CVE"),
    "kubernetes_misconfiguration": ("Kubernetes 配置风险", "Kubernetes Misconfiguration"),
    "sql_injection": ("SQL 注入", "SQL Injection"),
    "command_injection": ("命令注入", "Command Injection"),
    "cross_site_scripting": ("跨站脚本", "Cross-site Scripting"),
    "file_inclusion": ("文件包含", "File Inclusion"),
    "file_upload": ("文件上传风险", "File Upload"),
    "csrf": ("跨站请求伪造", "CSRF"),
    "cookie_security": ("Cookie 安全属性不足", "Insecure Cookie Attributes"),
    "information_disclosure": ("信息泄露", "Information Disclosure"),
    "subdomain_takeover": ("子域接管风险", "Subdomain Takeover"),
    "open_port": ("开放服务端口", "Open Service Port"),
    "api_contract_failure": ("API 契约异常", "API Contract Failure"),
    "ssrf": ("服务端请求伪造", "SSRF"),
    "xxe": ("XML 外部实体注入", "XXE"),
    "weak_session_id": ("弱会话标识", "Weak Session ID"),
    "session_fixation": ("会话固定", "Session Fixation"),
    "brute_force": ("登录限速缺失", "Missing Login Throttling"),
}


def severity_labels(value: str) -> tuple[str, str]:
    return SEVERITY_LABELS.get(value, (value, value))


def status_labels(value: str) -> tuple[str, str]:
    return STATUS_LABELS.get(value, (value, value))


def vuln_type_labels(value: str) -> tuple[str, str]:
    if value in VULN_TYPE_LABELS:
        return VULN_TYPE_LABELS[value]
    readable = value.replace("_", " ").replace("-", " ").strip()
    readable = readable[:1].upper() + readable[1:] if readable else "Unknown"
    return readable, readable
