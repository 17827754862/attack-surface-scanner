from __future__ import annotations

import json
from pathlib import Path

from app.dedup import merge_findings, normalize_vuln_type
from app.evidence import EvidenceStore
from app.lab_benchmark import (
    evaluate_lab_benchmark,
    run_lab_benchmark,
    suite_for_target,
    suite_requires_auth,
)
from app.redaction import redact
from app.report import render_report
from app.schemas.finding import Finding
from app.workflow_image import build_mermaid


def test_alias_confidence_and_corroboration() -> None:
    rows = [
        Finding(
            source="zap",
            host="dvwa",
            url="http://dvwa/",
            vuln_type="Content Security Policy (CSP) Header Not Set",
            severity="medium",
            evidence={"description": "missing"},
        ),
        Finding(
            source="wapiti",
            host="dvwa",
            url="http://dvwa/",
            vuln_type="Content Security Policy Configuration",
            severity="low",
            evidence={"info": "missing CSP"},
        ),
    ]
    merged = merge_findings(rows)
    assert len(merged) == 1
    assert merged[0].vuln_type == "missing_security_headers"
    assert merged[0].also_reported_by == ["wapiti"]
    assert 0 <= merged[0].confidence <= 100
    assert normalize_vuln_type("SQL Injection") == "sql_injection"


def test_evidence_store_hash_verification(tmp_path: Path) -> None:
    finding = Finding(
        source="nuclei",
        host="dvwa",
        url="http://dvwa/",
        vuln_type="CVE-2024-0001",
        severity="high",
        evidence={"matched": "x"},
        raw={"id": "x"},
    )
    store = EvidenceStore(str(tmp_path), "task")
    evidence_hash = store.write(finding)
    store.write_index([finding])
    payload = store.read_verified(evidence_hash)
    assert payload["fingerprint"] == finding.fingerprint
    assert store.find_by_fingerprint(finding.fingerprint) == evidence_hash


def test_report_contains_playbook_confidence_and_llm(tmp_path: Path) -> None:
    finding = Finding(
        source="nikto",
        host="dvwa",
        url="http://dvwa/",
        vuln_type="CSP Header Not Set",
        severity="medium",
        evidence={"status": "missing"},
        confidence=77,
    )
    result = render_report(
        task_id="abc",
        target="http://dvwa",
        status="completed",
        findings=[finding],
        node_status={"report": "done"},
        trace=[],
        output_dir=str(tmp_path),
        llm_summary={"text": "priority summary"},
        blocked_targets=["external: http://outside.invalid"],
        risk_groups=[
            {
                "key": "risk-1",
                "vuln_type": "missing_security_headers",
                "title_zh": "缺少安全响应头",
                "title_en": "Missing Security Headers",
                "severity": "medium",
                "instance_count": 1,
                "affected_url_count": 1,
                "affected_urls": ["http://dvwa/"],
                "sources": ["zap"],
                "analysis_source": "ai",
                "description_zh": "AI 解读内容",
                "description_en": "AI explanation",
                "reproduction_steps_zh": ["重新请求目标"],
                "false_positive_checks_zh": ["检查响应头"],
                "remediation_zh": ["补充安全响应头"],
            }
        ],
        memory_context={
            "scan_count": 2,
            "new_risk_types": ["missing_security_headers"],
            "persistent_risk_types": [],
            "resolved_risk_types": [],
        },
    )
    html = Path(result["html"]).read_text(encoding="utf-8")
    assert "priority summary" in html
    assert "missing_security_headers" in html or "CSP" in html
    assert finding.evidence_hash in html
    assert "已拦截越界目标" in html
    assert "覆盖范围说明" in html
    assert "历史记忆 / Historical Memory" in html
    assert "风险组 / Risk Groups" in html
    assert "AI 解读内容" in html
    assert "scrollbar-color:#35353a #050506" in html
    assert "*::-webkit-scrollbar-track{background:#050506}" in html
    assert result["png"]
    mermaid = Path(result["mermaid"]).read_text(encoding="utf-8")
    assert "flowchart TB" in mermaid
    assert '"background":"#050506"' in mermaid
    assert "style ROW1 fill:#09090b" in mermaid
    assert "START --> report" in mermaid
    assert "class report done" in mermaid
    payload = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
    assert payload["findings"][0]["playbook"]


def test_workflow_escapes_untrusted_summary() -> None:
    mermaid = build_mermaid(
        [
            {
                "node_name": "recon",
                "output_summary": 'x"]\n  style report fill:#ff0000',
            }
        ],
        {"recon": "done"},
    )

    assert "&quot;" in mermaid
    assert "\n  style report fill:#ff0000" not in mermaid
    assert "class recon done" in mermaid


def test_workflow_hides_tools_that_were_not_called() -> None:
    mermaid = build_mermaid(
        [
            {"node_name": "recon", "status": "done", "output_summary": "local target"},
            {
                "node_name": "takeover_check",
                "status": "skipped",
                "error": "local_targets_do_not_support_takeover_checks",
            },
            {
                "node_name": "credential_session_analysis",
                "status": "skipped",
                "error": "login_authentication_not_configured",
            },
            {"node_name": "http_probe", "status": "done", "output_summary": "live endpoints: 50"},
        ],
        {
            "recon": "done",
            "takeover_check": "skipped",
            "credential_session_analysis": "skipped",
            "http_probe": "done",
            "port_scan": "pending",
        },
    )

    assert 'subjack["' not in mermaid
    assert 'credential_session_analysis["' not in mermaid
    assert "local_targets_do_not_support_takeover_checks" not in mermaid
    assert "STEP 01" in mermaid
    assert "STEP 02" in mermaid
    assert "串行执行链 / Sequential chain" in mermaid


def test_redacts_secrets_recursively() -> None:
    payload = {
        "password": "secret",
        "nested": {"cookie": "sid=1", "safe": "value"},
        "message": "token=abc&username=admin",
        "authorization": "Bearer abc.def",
        "url": "https://user:password@dvwa/login.php",
    }
    redacted = redact(payload)
    assert redacted["password"] == "***"
    assert redacted["nested"]["cookie"] == "***"
    assert redacted["message"] == "token=***&username=admin"
    assert redacted["authorization"] == "***"
    assert redacted["url"] == "https://user:***@dvwa/login.php"


def test_dedup_preserves_ground_truth_ids_and_benchmark_recall() -> None:
    row = Finding(
        source="lab_benchmark",
        host="dvwa.test",
        url="http://dvwa.test/vulnerabilities/sqli/",
        vuln_type="sql_injection",
        severity="critical",
        evidence={
            "ground_truth_id": "DVWA-SQLI",
            "ground_truth_ids": ["DVWA-SQLI"],
        },
    )
    duplicate = Finding(
        source="active_validation",
        host="dvwa.test",
        url="http://dvwa.test/vulnerabilities/sqli/",
        vuln_type="sql_injection",
        severity="high",
        evidence={"ground_truth_ids": ["DVWA-CMDI"]},
    )
    merged = merge_findings([row, duplicate])

    assert len(merged) == 1
    assert merged[0].evidence["ground_truth_ids"] == ["DVWA-CMDI", "DVWA-SQLI"]
    benchmark = evaluate_lab_benchmark("http://dvwa.test", [merged[0].model_dump()])
    assert benchmark["matched"] == 2
    assert benchmark["total"] == 14
    assert benchmark["recall_percent"] == 14.29


def test_cve_benchmark_suite_detection() -> None:
    assert suite_for_target("http://cve-2019-14234.test") == "cve-2019-14234"
    assert not suite_requires_auth("cve-2019-14234")
    assert not suite_requires_auth("cve-2024-23334")
    benchmark = evaluate_lab_benchmark(
        "http://cve-2024-23334.test",
        [
            {
                "evidence": {
                    "ground_truth_id": "CVE-2024-23334",
                    "ground_truth_ids": ["CVE-2024-23334"],
                }
            }
        ],
    )
    assert benchmark["matched"] == 1
    assert benchmark["recall_percent"] == 100.0


def test_vampi_benchmark_suite_detection() -> None:
    assert suite_for_target("http://vampi.test") == "vampi"
    benchmark = evaluate_lab_benchmark(
        "http://vampi.test",
        [
            {
                "evidence": {
                    "ground_truth_id": "VAMPI-SQLI",
                    "ground_truth_ids": ["VAMPI-SQLI"],
                }
            }
        ],
    )
    assert benchmark["total"] == 8
    assert benchmark["matched"] == 1


def test_crapi_benchmark_suite_detection() -> None:
    assert suite_for_target("http://crapi.test") == "crapi"
    assert not suite_requires_auth("crapi")
    benchmark = evaluate_lab_benchmark(
        "http://crapi.test",
        [
            {
                "evidence": {
                    "ground_truth_id": "CRAPI-JWT-INVALID-SIGNATURE",
                    "ground_truth_ids": ["CRAPI-JWT-INVALID-SIGNATURE"],
                }
            }
        ],
    )
    assert benchmark["total"] == 6
    assert benchmark["matched"] == 1


def test_crapi_benchmark_probes_documented_safe_subset() -> None:
    class Response:
        def __init__(self, url: str, status_code: int, payload: object) -> None:
            self.url = url
            self.status_code = status_code
            self._payload = payload
            self.headers: dict[str, str] = {}
            self.cookies = self
            self.text = (
                payload
                if isinstance(payload, str)
                else __import__("json").dumps(payload)
            )

        def json(self) -> object:
            return self._payload

        def get(self, _name: str) -> str:
            return ""

    def request(method: str, url: str, **kwargs: object) -> Response:
        path = url.split("crapi.test", 1)[-1]
        if path == "/identity/api/auth/signup":
            return Response(url, 200, {"message": "registered"})
        if path == "/identity/api/auth/login":
            return Response(url, 200, {"token": "valid-token"})
        if "/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location" in path:
            return Response(url, 200, {"latitude": 32.7, "longitude": -91.9})
        if path == "/identity/api/v2/user/dashboard":
            headers = kwargs.get("headers") or {}
            if str(headers.get("Authorization", "")).endswith("."):
                return Response(url, 200, {"email": "adam007@example.com"})
            return Response(url, 200, {"available_credit": 100.0})
        if path == "/workshop/api/shop/products":
            return Response(url, 200, {"products": [{"id": 1, "price": 10}]})
        if path == "/workshop/api/shop/orders":
            return Response(url, 200, {"credit": 110.0})
        if path == "/workshop/api/shop/apply_coupon":
            return Response(
                url,
                400,
                {
                    "message": (
                        "TRAC075 Coupon code is already claimed by you!! "
                        "Please try with another coupon code"
                    )
                },
            )
        if path == "/identity/api/auth/v2/check-otp":
            return Response(url, 500, {"message": "Invalid OTP"})
        if path == "/workshop/api/merchant/contact_mechanic":
            return Response(
                url,
                200,
                {
                    "status": 200,
                    "response_from_mechanic_api": {"products": []},
                },
            )
        raise AssertionError(f"unexpected request: {method} {path}")

    findings = run_lab_benchmark("http://crapi.test", request)
    matched_ids = {
        finding.evidence["ground_truth_id"]
        for finding in findings
        if finding.evidence
    }
    assert matched_ids == {
        "CRAPI-BOLA-VEHICLE",
        "CRAPI-NEGATIVE-QUANTITY",
        "CRAPI-SQLI-COUPON",
        "CRAPI-OTP-BRUTE-FORCE",
        "CRAPI-JWT-INVALID-SIGNATURE",
        "CRAPI-SSRF-MECHANIC",
    }
