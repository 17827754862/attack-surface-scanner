from __future__ import annotations

import re
import time
import urllib.parse
import urllib.request
import uuid
from typing import Any

from ..auth_session import AuthSession, authenticate
from ..config import settings
from ..schemas.finding import Finding
from .base import AdapterCancelled, BaseAdapter


def _parse_cookie_header(value: str) -> dict[str, str]:
    output: dict[str, str] = {}
    for item in value.split(";"):
        if "=" not in item:
            continue
        name, cookie_value = item.split("=", 1)
        if name.strip():
            output[name.strip()] = cookie_value.strip()
    return output


class ZapAdapter(BaseAdapter):
    name = "zap"
    tool_version = "2.17.0"

    def available(self) -> bool:
        if not settings.zap_url:
            return False
        query = urllib.parse.urlencode({"apikey": settings.zap_api_key})
        url = (
            f"{settings.zap_url.rstrip('/')}/JSON/core/view/version/"
            f"?{query}"
        )
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if 200 <= response.status < 300:
                    return True
        except Exception:
            pass
        capability = self.capabilities.get(self.name)
        return bool(capability.get("available")) if capability is not None else False

    def run(self, target_or_input: Any, options: dict[str, Any]) -> list[Finding]:
        if not self.available():
            return []
        try:
            import zapv2
        except ImportError:
            return []
        targets = target_or_input if isinstance(target_or_input, list) else [target_or_input]
        origins: list[str] = []
        seen_origins: set[str] = set()
        for target in targets:
            parsed = urllib.parse.urlparse(str(target).strip())
            origin = (
                f"{parsed.scheme}://{parsed.netloc}"
                if parsed.scheme and parsed.netloc
                else str(target).strip().rstrip("/")
            )
            if origin and origin not in seen_origins:
                seen_origins.add(origin)
                origins.append(origin)
        targets = origins
        client = zapv2.ZAPv2(
            proxies={"http": settings.zap_url, "https": settings.zap_url},
            apikey=settings.zap_api_key,
        )
        try:
            client.core.new_session(apikey=settings.zap_api_key)
        except Exception:
            client.core.new_session()
        findings: list[Finding] = []
        errors: list[str] = []
        rate = self._rate(options)
        auth_result = (
            authenticate(str(options.get("auth_ref") or ""))
            if options.get("auth_scan")
            else None
        )
        if auth_result and not auth_result.authenticated:
            raise RuntimeError("authentication_failed")
        context_name = f"scan-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
        for target in [str(item) for item in targets if str(item)]:
            cookie_rule = ""
            context_id = ""
            try:
                self._check_cancel()
                client.ascan.set_option_thread_per_host(1)
                client.ascan.set_option_delay_in_ms(max(0, int(1000 / rate)))
                try:
                    client.ascan.disable_scanners("10104")
                except Exception:
                    pass
                client.spider.set_option_max_children(max(1, rate))
                client.spider.set_option_process_form(False)
                context_id = client.context.new_context(context_name)
                try:
                    client.context.set_context_in_scope(context_name, True)
                except Exception:
                    pass
                host = urllib.parse.urlparse(target).hostname or target
                client.context.include_in_context(
                    context_name,
                    rf"https?://{host}(:\d+)?(/.*)?",
                )
                excluded_paths = list(
                    dict.fromkeys(
                        [
                            *(options.get("safe_path_denylist") or []),
                            *(options.get("active_scan_exclude") or []),
                        ]
                    )
                )
                for excluded_path in excluded_paths:
                    try:
                        client.context.exclude_from_context(
                            context_name,
                            rf"https?://{re.escape(host)}(:\d+)?/"
                            rf"{re.escape(str(excluded_path).lstrip('/'))}"
                            r"(?:\?.*)?$",
                        )
                    except Exception:
                        pass
                if auth_result and auth_result.authenticated:
                    cookie_rule = self._install_session_auth(
                        client,
                        target,
                        auth_result,
                    )
                if (
                    options.get("mode") == "full"
                    and options.get("tool_profile") == "full_agent"
                ):
                    try:
                        self._run_ajax_spider(client, target)
                    except AdapterCancelled:
                        raise
                    except Exception as exc:
                        errors.append(f"{target}: ajax_spider: {exc}")
                user_id = ""
                if user_id:
                    scan_id = client.spider.scan_as_user(
                        context_id,
                        user_id,
                        url=target,
                        recurse=True,
                    )
                else:
                    scan_id = client.spider.scan(
                        target,
                        recurse=True,
                        contextname=context_name,
                    )
                if not str(scan_id).strip().isdigit():
                    raise RuntimeError(f"spider_start_failed: {scan_id}")
                self._wait(
                    lambda: int(client.spider.status(scan_id)),
                    stop_fn=client.spider.stop_all_scans,
                )
                if options.get("auth_scan"):
                    metrics = options.setdefault("auth_metrics", {})
                    metrics["authenticated"] = bool(cookie_rule or user_id)
                    try:
                        metrics["url_count"] = len(
                            client.context.urls(context_name)
                        )
                    except Exception:
                        metrics["url_count"] = len(client.core.urls())
                    metrics["session_source"] = (
                        "replacer" if cookie_rule else "none"
                    )
                if user_id:
                    ascan_id = client.ascan.scan_as_user(
                        url=target,
                        contextid=context_id,
                        userid=user_id,
                        recurse=True,
                    )
                else:
                    ascan_id = client.ascan.scan(
                        url=target,
                        recurse=True,
                        contextid=context_id,
                    )
                if not str(ascan_id).strip().isdigit():
                    raise RuntimeError(f"ascan_start_failed: {ascan_id}")
                self._wait(
                    lambda: int(client.ascan.status(ascan_id)),
                    stop_fn=client.ascan.stop_all_scans,
                )
                alerts = client.core.alerts(baseurl=target)
            except AdapterCancelled:
                raise
            except Exception as exc:
                errors.append(f"{target}: {exc}")
                continue
            finally:
                if cookie_rule:
                    try:
                        client.replacer.remove_rule(cookie_rule)
                    except Exception:
                        pass
                try:
                    client.context.remove_context(context_name)
                except Exception:
                    pass
            findings.extend(self.parse_alerts(alerts, target))
        if errors and not findings:
            raise RuntimeError("; ".join(errors))
        return self._filter_findings(findings, options)

    def _run_ajax_spider(self, client: Any, target: str) -> None:
        try:
            client.ajaxSpider.set_option_max_crawl_depth(5)
            client.ajaxSpider.set_option_number_of_browsers(1)
        except Exception:
            pass
        try:
            client.ajaxSpider.scan(target, inscope="true")
        except TypeError:
            client.ajaxSpider.scan(target)
        self._wait(
            lambda: (
                100
                if str(client.ajaxSpider.status).lower() != "running"
                else 0
            ),
            stop_fn=client.ajaxSpider.stop,
        )

    @staticmethod
    def _install_cookie_auth(client: Any, target: str, cookie_header: str) -> str:
        return ZapAdapter._install_session_auth(
            client,
            target,
            AuthSession(authenticated=True, cookies=_parse_cookie_header(cookie_header)),
        )

    @staticmethod
    def _install_session_auth(
        client: Any,
        target: str,
        session: AuthSession,
    ) -> str:
        headers = session.request_headers()
        if not headers:
            return ""
        host = urllib.parse.urlparse(target).hostname or target
        description = f"scanner-auth-{uuid.uuid4().hex}"
        extra = "".join(
            f"\r\n{name}: {value}"
            for name, value in headers.items()
            if name.lower() != "user-agent"
        )
        replacement = f"$0{extra}"
        client.replacer.add_rule(
            description,
            True,
            "REQ_HEADER_STR",
            True,
            r"(?im)^User-Agent:.*$",
            replacement,
            url=rf"https?://{re.escape(host)}(?::\d+)?(?:/.*)?",
        )
        return description

    def _wait(self, status_fn, stop_fn=None) -> None:
        try:
            while True:
                self._check_cancel()
                if status_fn() >= 100:
                    return
                time.sleep(2)
        except AdapterCancelled:
            if stop_fn:
                try:
                    stop_fn()
                except Exception:
                    pass
            raise

    @staticmethod
    def parse_alerts(alerts: list[dict[str, Any]], target: str) -> list[Finding]:
        risk_map = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
        }
        output: list[Finding] = []
        for alert in alerts:
            if str(alert.get("pluginId") or "") == "10104":
                continue
            risk = str(alert.get("risk") or "informational").lower()
            output.append(
                Finding(
                    source="zap",
                    host=str(alert.get("host") or ""),
                    url=str(alert.get("url") or target),
                    vuln_type=str(alert.get("alert") or "zap alert"),
                    severity=risk_map.get(risk, "info"),  # type: ignore[arg-type]
                    evidence={
                        "plugin_id": alert.get("pluginId"),
                        "risk": risk,
                        "confidence": alert.get("confidence"),
                        "description": alert.get("description"),
                    },
                    raw=alert,
                )
            )
        return output
