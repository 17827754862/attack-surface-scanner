from __future__ import annotations

import subprocess

import pytest

from app import capabilities


def test_extract_version_skips_ansi_and_ascii_art() -> None:
    wapiti = """
██╗    ██╗ █████╗ ██████╗ ██╗████████╗██╗██████╗
╚██╗  ██╔╝██╔══██╗██╔══██╗██║╚══██╔══╝██║██╔══██╗
3.3.2
"""
    nuclei = "\x1b[34mINF\x1b[0m Nuclei Engine Version: v3.11.1"

    assert capabilities._extract_version("wapiti", wapiti) == "3.3.2"
    assert capabilities._extract_version("nuclei", nuclei) == "3.11.1"
    assert capabilities._extract_version("subjack", "Usage: subjack [options]") == "3.1.0"


def test_openvas_capability_uses_gvm_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENVAS_ENABLED", "true")
    monkeypatch.setenv("OPENVAS_HOST", "openvas")
    monkeypatch.setenv("OPENVAS_PORT", "9390")
    monkeypatch.setattr(capabilities.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(capabilities, "_probe_tcp", lambda *_args: True)
    calls: list[list[str]] = []

    def fake_run(command, **_kwargs):
        calls.append(list(command))
        if "<get_version/>" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                "<get_version_response><version>26.1</version></get_version_response>",
                "",
            )
        return subprocess.CompletedProcess(
            command,
            0,
            "<get_feeds_response><feed><status>current</status></feed></get_feeds_response>",
            "",
        )

    monkeypatch.setattr(capabilities.subprocess, "run", fake_run)
    result = capabilities._probe_openvas()
    assert result["available"] is True
    assert result["version"] == "26.1"
    assert calls and all(command[0] == "gvm-cli" for command in calls)
