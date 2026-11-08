"""Unit tests for the Stage 1 lab-only discovery entry point.

No live scans or WT-96 parser are required for these unit tests.
"""

import subprocess
from pathlib import Path

import pytest

from lab import discover_c1


NMAP_XML = '''<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn --privileged -oX /tmp/quick.xml --exclude 172.28.0.6 172.28.0.0/24" version="7.95" start="1794000000">
  <host><status state="up"/><address addr="172.28.0.2" addrtype="ipv4"/>
    <address addr="50:C7:BF:11:00:02" addrtype="mac" vendor="TP-Link Technologies"/>
  </host>
  <runstats><finished time="1794000002"/></runstats>
</nmaprun>
'''


def test_quick_scan_passes_xml_to_c1_parser(monkeypatch):
    monkeypatch.setenv("WATCHTOWER_CONFIG", discover_c1.DEV_CONFIG)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "ip":
            return subprocess.CompletedProcess(
                cmd, 0,
                stdout="11: eth0@if30 inet 172.28.0.6/24 brd 172.28.0.255 scope global eth0\n",
            )
        assert cmd[:4] == ["nmap", "-sn", "--privileged", "-oX"]
        assert cmd[-3:] == ["--exclude", "172.28.0.6", "172.28.0.0/24"]
        Path(cmd[4]).write_text(NMAP_XML, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="")

    def fake_parser(xml_path):
        assert Path(xml_path).read_text(encoding="utf-8") == NMAP_XML
        return {
            "scan_id": "example-scan", "profile": "quick",
            "subnet": "172.28.0.0/24", "started_at": "example-start",
            "finished_at": "example-end", "nmap_version": "7.95",
            "hosts": [{
                "ip": "172.28.0.2", "mac": "50:C7:BF:11:00:02",
                "vendor": "TP-Link Technologies", "mac_randomised": False,
                "hostname": None, "os_guess": None, "ports": [],
            }],
        }

    monkeypatch.setattr(discover_c1.subprocess, "run", fake_run)
    monkeypatch.setattr(discover_c1, "parse_scan_xml", fake_parser)
    result = discover_c1.discover_c1()

    assert len(calls) == 2
    assert result["profile"] == "quick"
    assert result["subnet"] == "172.28.0.0/24"
    assert result["hosts"][0]["ip"] == "172.28.0.2"
    assert result["hosts"][0]["ports"] == []


def test_wrong_subnet_refused_before_scan(monkeypatch):
    monkeypatch.setenv("WATCHTOWER_CONFIG", discover_c1.DEV_CONFIG)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(
            cmd, 0, stdout="11: eth0 inet 192.168.1.10/24 scope global eth0\n"
        )

    monkeypatch.setattr(discover_c1.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="Refusing scan"):
        discover_c1.discover_c1()
    assert len(calls) == 1
    assert calls[0][0] == "ip"


def test_requires_dev_configuration(monkeypatch):
    monkeypatch.delenv("WATCHTOWER_CONFIG", raising=False)
    with pytest.raises(RuntimeError, match="configured lab scanner"):
        discover_c1.discover_c1()
