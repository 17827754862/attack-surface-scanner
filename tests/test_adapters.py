from __future__ import annotations

import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from app.adapters.dnsx import DnsxAdapter
from app.adapters.gitleaks_adapter import GitleaksAdapter
from app.adapters.httpx_adapter import HttpxAdapter
from app.adapters.kubescape_adapter import KubescapeAdapter
from app.adapters.nikto_adapter import NiktoAdapter
from app.adapters.nmap_adapter import NmapAdapter
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.openvas_adapter import OpenvasAdapter
from app.adapters.schemathesis_adapter import SchemathesisAdapter
from app.adapters.subfinder import SubfinderAdapter
from app.adapters.subjack_adapter import SubjackAdapter
from app.adapters.wapiti_adapter import WapitiAdapter
from app.adapters.zap_adapter import ZapAdapter
from app.auth_session import AuthSession
from app.guard import ScopeDecision


CAPS = {
    name: {"available": True}
    for name in (
        "subfinder",
        "dnsx",
        "httpx",
        "nmap",
        "nuclei",
        "zap",
        "openvas",
        "schemathesis",
        "kubescape",
        "subjack",
        "gitleaks",
        "nikto",
        "wapiti",
    )
}


@pytest.fixture(autouse=True)
def allow_scope(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "app.adapters.base.validate_scope",
        lambda candidate, scope, cidrs: ScopeDecision(
            candidate,
            candidate.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0],
            ["dvwa"],
            ["172.19.0.2"],
        ),
    )


def completed(command: list[str], stdout: str = "", code: int = 0):
    return subprocess.CompletedProcess(command, code, stdout, "")


OPTIONS = {
    "max_rps": 5,
    "scope": ["dvwa"],
    "allowed_cidrs": ["172.16.0.0/12"],
    "blocked_targets": [],
}


def test_subfinder_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = SubfinderAdapter(CAPS)
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: completed([], '{"host":"a.dvwa"}\n'),
    )
    findings = adapter.run("dvwa", OPTIONS)
    assert findings[0].source == "subfinder"
    assert findings[0].host == "a.dvwa"


def test_dnsx_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = DnsxAdapter(CAPS)
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: completed([], "a.dvwa [172.19.0.2]\n"),
    )
    assert adapter.run(["a.dvwa"], OPTIONS)[0].host == "a.dvwa"


def test_httpx_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = HttpxAdapter(CAPS)
    row = {"url": "http://dvwa/", "host": "dvwa", "port": 80, "status_code": 200}
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: completed([], json.dumps(row) + "\n"),
    )
    findings = adapter.run(["http://dvwa"], OPTIONS)
    assert findings[0].url == "http://dvwa/"


def test_nmap_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    xml = """<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="8081"><state state="open"/>
    <service name="http" product="Apache" version="2.4"/></port></ports>
    </host></nmaprun>"""
    adapter = NmapAdapter(CAPS)
    monkeypatch.setattr(adapter, "_run", lambda *_args, **_kwargs: completed([], xml))
    findings = adapter.run(["dvwa"], OPTIONS)
    assert findings[0].port == 8081


def test_nuclei_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    row = {
        "template-id": "test",
        "host": "dvwa",
        "matched-at": "http://dvwa/",
        "info": {"name": "SQL Injection", "severity": "high"},
    }
    adapter = NucleiAdapter(CAPS)
    commands: list[list[str]] = []

    def fake_run(command, input_text=None, **_kwargs):
        commands.append(command)
        assert input_text == "http://dvwa\n"
        return completed([], json.dumps(row) + "\n")

    monkeypatch.setattr(
        adapter,
        "_run",
        fake_run,
    )
    assert adapter.run(["http://dvwa"], OPTIONS)[0].severity == "high"
    assert commands[0][commands[0].index("-t") + 1] == "/opt/nuclei-templates"
    assert commands[0][1:3] == ["-l", "-"]


def test_zap_adapter_authenticated_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    class Context:
        def new_context(self, _name): calls.append("new_context"); return "1"
        def include_in_context(self, *_args): calls.append("include")
        def set_context_in_scope(self, *_args): calls.append("in_scope")
        def exclude_from_context(self, *_args): calls.append("exclude")
        def urls(self, _name): return ["http://dvwa/", "http://dvwa/vulnerabilities/exec/"]
        def remove_context(self, _name): calls.append("remove")

    class Spider:
        def set_option_max_children(self, *_args): pass
        def set_option_process_form(self, _enabled): calls.append("no_forms")
        def scan(self, *_args, **_kwargs): calls.append("spider"); return "9"
        def status(self, _id): return "100"
        def stop_all_scans(self): pass

    class Ascan:
        def set_option_thread_per_host(self, *_args): pass
        def set_option_delay_in_ms(self, *_args): pass
        def set_option_max_scan_duration_in_mins(self, *_args): pass
        def set_option_max_rule_duration_in_mins(self, *_args): pass
        def scan(self, *_args, **_kwargs): calls.append("ascan"); return "10"
        def status(self, _id): return "100"
        def stop_all_scans(self): pass

    class AjaxSpider:
        def set_option_max_duration(self, *_args): pass
        def set_option_max_crawl_depth(self, *_args): pass
        def set_option_number_of_browsers(self, *_args): pass
        def scan(self, *_args): calls.append("ajax_spider"); return "OK"
        def status(self): return "stopped"
        def stop(self): pass

    class Core:
        def new_session(self, **_kwargs): calls.append("new_session")
        def alerts(self, baseurl=None):
            return [{
                "alert": "Missing Anti-clickjacking Header",
                "risk": "Medium",
                "confidence": "High",
                "host": "dvwa",
                "url": baseurl,
                "pluginId": "10020",
            }]
        def urls(self): return ["a", "b", "c"]

    class Replacer:
        def add_rule(self, description, *_args, **_kwargs):
            calls.append("cookie_rule")
            assert "PHPSESSID=test" in _args[4]
            return "OK"

        def remove_rule(self, description):
            calls.append("remove_cookie_rule")

    fake = SimpleNamespace(
        context=Context(),
        spider=Spider(),
        ascan=Ascan(),
        ajaxSpider=AjaxSpider(),
        core=Core(),
        replacer=Replacer(),
    )
    monkeypatch.setattr(
        "app.adapters.zap_adapter.authenticate",
        lambda _auth_ref: AuthSession(
            authenticated=True,
            cookies={"PHPSESSID": "test", "security": "low"},
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "zapv2",
        SimpleNamespace(ZAPv2=lambda **_kwargs: fake),
    )
    options = {
        **OPTIONS,
        "auth_scan": True,
        "auth_ref": "local-dvwa",
        "mode": "full",
        "tool_profile": "full_agent",
        "blocked_targets": [],
        "safe_path_denylist": [],
        "active_scan_exclude": [],
    }
    adapter = ZapAdapter(CAPS)
    findings = adapter.run(
        ["http://dvwa", "http://dvwa/vulnerabilities/exec/"],
        options,
    )
    assert findings and findings[0].source == "zap"
    assert "spider" in calls and "ascan" in calls and "ajax_spider" in calls
    assert calls.count("spider") == 1
    assert calls.count("ascan") == 1
    assert "new_session" in calls and "cookie_rule" in calls
    assert "remove_cookie_rule" in calls
    assert options["auth_metrics"]["authenticated"] is True
    assert options["auth_metrics"]["url_count"] == 2
    assert options["auth_metrics"]["session_source"] == "replacer"


def test_openvas_adapter_full_gmp_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = OpenvasAdapter({**CAPS, "openvas": {"available": True}})
    monkeypatch.setattr("app.config.settings.openvas_enabled", True)
    calls: list[str] = []

    def fake_call(xml: str) -> str:
        calls.append(xml)
        if "<get_configs/>" in xml:
            return "<get_configs_response><config id='cfg'><name>Full and fast</name></config></get_configs_response>"
        if "<get_scanners/>" in xml:
            return "<get_scanners_response><scanner id='scan'><name>OpenVAS Default</name></scanner></get_scanners_response>"
        if "<create_target>" in xml:
            assert "<hosts>dvwa</hosts>" in xml
            assert "<port_range>T:1-65535</port_range>" in xml
            return "<create_target_response status='201' id='target'/>"
        if "<create_task>" in xml:
            return "<create_task_response status='201' id='task'/>"
        if "<start_task" in xml:
            return "<start_task_response status='200'/>"
        if "<get_tasks" in xml:
            return (
                "<get_tasks_response><task><status>Done</status>"
                "<last_report><report id='report'><timestamp>now</timestamp>"
                "</report></last_report></task></get_tasks_response>"
            )
        if "<get_report" in xml:
            return """<get_report_response><report><results><result><name>Test CVE</name>
            <host>dvwa</host><severity>7.5</severity><port>80/tcp</port>
            </result></results></report></get_report_response>"""
        return "<response status='200'/>"

    monkeypatch.setattr(adapter, "_call", fake_call)
    findings = adapter.run("http://dvwa", OPTIONS)
    assert findings[0].severity == "high"
    assert findings[0].source == "openvas"
    assert any("<start_task" in item for item in calls)
    assert any("<get_report" in item for item in calls)


def test_openvas_uses_gvm_cli_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = OpenvasAdapter({**CAPS, "openvas": {"available": True}})
    captured: list[str] = []
    monkeypatch.setenv("OPENVAS_CAFILE", "/gvm-secure/cacert.pem")

    def fake_run(command, input_text=None):
        captured.extend(command)
        return completed(["gvm-cli"], "<get_version_response/>")

    monkeypatch.setattr(adapter, "_run", fake_run)
    assert adapter._call("<get_version/>") == "<get_version_response/>"
    assert captured[0] == "gvm-cli"
    assert "--gmp-password" in captured
    assert "--cafile" in captured
    assert "/gvm-secure/cacert.pem" in captured
    assert "--timeout" not in captured
    assert "--raw" not in captured


def test_schemathesis_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = SchemathesisAdapter(CAPS)
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: completed([], "failure", code=1),
    )
    findings = adapter.run(["http://dvwa/openapi.json"], OPTIONS)
    assert findings[0].vuln_type == "api_contract_failure"


def test_kubescape_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = KubescapeAdapter(CAPS)
    monkeypatch.setenv("KUBECONFIG", "/tmp/kubeconfig")
    payload = {
        "summaryDetails": {
            "controls": {
                "C-1": {"status": "failed", "name": "Privileged container"}
            }
        }
    }
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: completed([], json.dumps(payload)),
    )
    assert adapter.run("dvwa", OPTIONS)[0].source == "kubescape"


def test_subjack_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = SubjackAdapter(CAPS)
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: completed([], "a.dvwa [Vulnerable]\n"),
    )
    assert adapter.run(["a.dvwa"], OPTIONS)[0].severity == "high"


def test_gitleaks_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = GitleaksAdapter(CAPS)
    monkeypatch.setattr(
        adapter,
        "_candidate_allowed",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        "app.adapters.gitleaks_adapter.httpx.get",
        lambda *_args, **_kwargs: SimpleNamespace(
            is_redirect=False,
            url="http://dvwa/app.js",
            text="token=secret",
        ),
    )
    payload = [{"File": "script-0.js", "RuleID": "generic-api-key", "Description": "key"}]
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: completed([], json.dumps(payload)),
    )
    findings = adapter.run(["http://dvwa/app.js"], OPTIONS)
    assert findings[0].source == "gitleaks"


def test_nikto_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = NiktoAdapter(CAPS)
    payload = [{"id": "1", "msg": "Missing header"}]
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *_args, **_kwargs: completed([], json.dumps(payload)),
    )
    assert adapter.run(["http://dvwa"], OPTIONS)[0].source == "nikto"


def test_wapiti_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = WapitiAdapter(CAPS)
    monkeypatch.setattr(
        adapter,
        "_login_cookie",
        lambda _auth_ref: ("PHPSESSID=test; security=low", True),
    )

    def fake_run(command):
        assert "-C" in command
        assert "PHPSESSID=test; security=low" in command
        assert "--max-scan-time" not in command
        assert "--max-attack-time" not in command
        assert command.count("-x") == 3
        assert "http://dvwa/logout.php" in command
        assert "http://dvwa/setup.php" in command
        assert "http://dvwa/vulnerabilities/csrf/" in command
        output = command[command.index("-o") + 1]
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "vulnerabilities": {
                        "SQL Injection": [
                            {
                                "level": 3,
                                "parameter": "id",
                                "info": "SQLi",
                                "path": "/vulnerabilities/sqli/?id=1",
                            }
                        ]
                    }
                },
                handle,
            )
        return completed(command)

    monkeypatch.setattr(adapter, "_run", fake_run)
    options = {
        **OPTIONS,
        "auth_scan": True,
        "auth_ref": "local-dvwa",
        "auth_metrics": {},
        "safe_path_denylist": ["logout.php", "setup.php"],
        "active_scan_exclude": ["vulnerabilities/csrf/"],
    }
    findings = adapter.run(["http://dvwa"], options)
    assert findings[0].severity == "high"
    assert findings[0].url == "http://dvwa/vulnerabilities/sqli/?id=1"
    assert findings[0].host == "dvwa"
    assert options["auth_metrics"]["wapiti_authenticated"] is True


def test_wapiti_reuses_generic_authenticated_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "app.adapters.wapiti_adapter.authenticate",
        lambda _auth_ref: AuthSession(
            authenticated=True,
            cookies={"PHPSESSID": "abc123", "security": "low"},
        ),
    )
    cookie, authenticated = WapitiAdapter._login_cookie("local-dvwa")
    assert authenticated is True
    assert cookie == "PHPSESSID=abc123; security=low"
