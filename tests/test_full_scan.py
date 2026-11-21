"""WT-FR-10 / TC-06: a full scan finds every inventory TCP port and its service.

NmapEngine is driven with a stand-in subprocess that emits a saved -sS -sV
fixture. Nothing here starts Nmap or touches a network. The live lab test
(WT-54) is Fatima's later CI job.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from watchtower.scanner import scan_engine
from watchtower.scanner.command_builder import build_command
from watchtower.scanner.models import Host, Port, ScanResult
from watchtower.scanner.nmap_parser import parse_nmap_xml
from watchtower.scanner.scan_engine import NmapEngine

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
INVENTORY_PATH = ROOT / "lab" / "inventory.yaml"
FULL_INVENTORY_XML = FIXTURES / "lab-full.xml"
LAB_NETWORK = "172.28.0.0/24"
SCANNER_IP = (
    "172.28.0.20"  # Fatima: devices are from .2 to .9 so scanner is .20 to avoid collisions
)


# TEMPORARY: MQTT port 1883 is listening on the smart plug, but the
# current full profile uses --top-ports 1000 and does not scan it.
# Cliff is updating the profile to include this port.
# Remove this exception and regenerate the fixture when that change lands.
PENDING_PROFILE_PORTS = {
    ("smart-plug", 1883),
}

# Product and version the current lab images expose, as recorded in the
# WT-55 lab-full.xml -sV output. Not every open port has these: BusyBox httpd
# and the socat SSH/RTSP banners often come back as a service name only.
LAB_SET_SERVICE = {
    ("router", 53): ("domain", "dnsmasq", "2.90"),
    ("camera", 23): ("telnet", "BusyBox telnetd", None),
    ("nas", 21): ("ftp", "vsftpd", "2.0.8 or later"),
    ("nas", 445): ("netbios-ssn", "Samba smbd", "4"),
}


def _load_inventory() -> list[dict]:
    data = yaml.safe_load(INVENTORY_PATH.read_text(encoding="utf-8"))
    devices = data["devices"]
    assert devices, "lab/inventory.yaml should list devices"
    return devices


def _hosts_by_mac(result: ScanResult) -> dict[str, Host]:
    return {host.mac.lower(): host for host in result.hosts if host.mac}


def _open_tcp_ports(host: Host) -> dict[int, Port]:
    return {
        port.port: port for port in host.ports if port.protocol == "tcp" and port.state == "open"
    }


def test_tc06_full_scan_finds_every_inventory_port(monkeypatch: pytest.MonkeyPatch) -> None:
    xml = FULL_INVENTORY_XML.read_text(encoding="utf-8")
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(list(argv))
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 1800
        assert argv[argv.index("-oX") + 1] == "-"
        return subprocess.CompletedProcess(argv, 0, stdout=xml, stderr="")

    monkeypatch.setattr(scan_engine.subprocess, "run", fake_run)
    result = NmapEngine(exclude_ip=SCANNER_IP).run("full", LAB_NETWORK)

    assert seen == [build_command("full", LAB_NETWORK, SCANNER_IP)]
    assert "-sS" in seen[0] and "-sV" in seen[0]
    assert isinstance(result, ScanResult)
    assert result.profile == "full"
    assert result.subnet == LAB_NETWORK

    parsed = ScanResult.from_dict(parse_nmap_xml(FULL_INVENTORY_XML, profile="full"))
    parsed_by_mac = _hosts_by_mac(parsed)
    found_by_mac = _hosts_by_mac(result)

    for device in _load_inventory():
        name = device["name"]
        mac = device["mac"].lower()
        assert mac in found_by_mac, f"{name} ({device['mac']}) missing from the full scan"
        found_ports = _open_tcp_ports(found_by_mac[mac])
        expected_ports = _open_tcp_ports(parsed_by_mac[mac])

        for port_number in device["ports"]:
            # Temporary stand-in until the full profile includes MQTT/1883.
            if (name, port_number) in PENDING_PROFILE_PORTS:
                continue
            assert port_number in found_ports, f"{name} is missing open TCP port {port_number}"
            port = found_ports[port_number]
            assert port.service, f"{name} port {port_number} has no service name"

            expected = expected_ports[port_number]
            if expected.product is not None:
                assert port.product == expected.product
            if expected.version is not None:
                assert port.version == expected.version

            lab_set = LAB_SET_SERVICE.get((name, port_number))
            if lab_set is not None:
                assert (port.service, port.product, port.version) == lab_set


def test_inventory_fixture_lists_every_inventory_mac() -> None:
    # Keeps lab-full-inventory.xml aligned with lab/inventory.yaml.
    parsed = ScanResult.from_dict(parse_nmap_xml(FULL_INVENTORY_XML))
    fixture_macs = set(_hosts_by_mac(parsed))
    inventory_macs = {device["mac"].lower() for device in _load_inventory()}
    assert inventory_macs <= fixture_macs
