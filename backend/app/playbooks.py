from __future__ import annotations

from pathlib import Path

from .config import settings
from .dedup import normalize_vuln_type


BOOK_BY_TYPE = {
    "default_credentials": "默认口令.md",
    "sensitive_file_exposure": "敏感文件.md",
    "missing_security_headers": "缺安全头.md",
    "cleartext_login": "明文登录.md",
    "known_cve": "CVE.md",
    "kubernetes_misconfiguration": "K8s配置.md",
    "sql_injection": "SQLi.md",
    "command_injection": "命令注入.md",
    "cross_site_scripting": "XSS.md",
    "file_inclusion": "文件包含.md",
    "file_upload": "文件上传.md",
    "csrf": "CSRF.md",
    "ssrf": "SSRF.md",
    "xxe": "XXE.md",
    "weak_session_id": "会话安全.md",
    "session_fixation": "会话安全.md",
    "brute_force": "登录防护.md",
}


def playbook_for(vuln_type: str) -> tuple[str, str]:
    normalized = normalize_vuln_type(vuln_type)
    filename = BOOK_BY_TYPE.get(normalized, "")
    if not filename:
        return "", ""
    path = Path(settings.playbook_dir) / filename
    if not path.exists():
        return filename, ""
    return filename, path.read_text(encoding="utf-8")
