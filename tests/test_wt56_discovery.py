"""Tests for WT-56 quick discovery MAC enrichment."""

import ipaddress
import subprocess
from pathlib import Path

import pytest
import yaml

from watchtower.scanner import scan_engine
from watchtower.scanner.mac_helpers import PRIVATE_ADDRESS_VENDOR
from watchtower.scanner.scan_engine import FakeEngine, NmapEngine

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NETWORK = "172.28.0.0/24"


@pytest.mark.parametrize("engine_type", ["fake", "nmap"])
def test_quick_discovery_applies_mac_helpers(
    monkeypatch: pytest.MonkeyPatch, engine_type: str
) -> None:
    if engine_type == "fake":
        result = FakeEngine(FIXTURES).run("quick", NETWORK)
    else:
        xml = (FIXTURES / "lab-quick.xml").read_text(encoding="utf-8")

        def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 0, stdout=xml, stderr="")

        monkeypatch.setattr(scan_engine.subprocess, "run", fake_run)
        result = NmapEngine(exclude_ip="172.28.0.20").run("quick", NETWORK)

    assert result.profile == "quick"
    assert result.hosts
    assert all(host.ports == [] for host in result.hosts)

    # MAC addresses should be normalized.
    for host in result.hosts:
        assert host.ip
        if host.mac is not None:
            assert host.mac == host.mac.lower()

    # Private addresses should receive the WT-57 vendor label.
    private_hosts = [host for host in result.hosts if host.mac_randomised]
    assert private_hosts
    assert all(host.vendor == PRIVATE_ADDRESS_VENDOR for host in private_hosts)

    # Known vendors should still be preserved.
    known_hosts = [host for host in result.hosts if host.vendor and not host.mac_randomised]
    assert known_hosts


@pytest.mark.parametrize("profile", ["quick", "full"])
def test_mac_enrichment_preserves_device_fields(profile: str) -> None:
    from watchtower.scanner.nmap_parser import parse_nmap_xml

    raw = parse_nmap_xml(FIXTURES / f"lab-{profile}.xml", profile=profile)
    result = FakeEngine(FIXTURES).run(profile, NETWORK)

    assert len(result.hosts) == len(raw["hosts"])

    for host, original in zip(result.hosts, raw["hosts"], strict=True):
        assert host.ip == original["ip"]
        assert host.hostname == original["hostname"]
        assert [port.to_dict() for port in host.ports] == original["ports"]

        if host.mac_randomised:
            assert host.vendor == PRIVATE_ADDRESS_VENDOR
        else:
            assert host.vendor == original["vendor"]


def test_quick_discovery_matches_lab_inventory() -> None:
    """Check that quick discovery includes every expected lab device."""
    inventory_path = Path(__file__).resolve().parents[1] / "lab" / "inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    devices = inventory["devices"]

    result = FakeEngine(FIXTURES).run("quick", NETWORK)

    # Docker's bridge gateway is not an inventory device.
    hosts = [host for host in result.hosts if host.ip != "172.28.0.1"]

    expected_macs = {device["mac"].lower() for device in devices}
    actual_macs = {host.mac for host in hosts}

    assert len(hosts) == len(devices)
    assert actual_macs == expected_macs

    network = ipaddress.ip_network(NETWORK)

    for host in hosts:
        assert ipaddress.ip_address(host.ip) in network
        assert host.mac is not None
        assert host.ports == []

    # These two devices use locally administered MAC addresses.
    hosts_by_mac = {host.mac: host for host in hosts}

    for device in devices:
        host = hosts_by_mac[device["mac"].lower()]
        expected_private = device["name"] in {"laptop", "phone"}

        assert host.mac_randomised is expected_private

        if expected_private:
            assert host.vendor == PRIVATE_ADDRESS_VENDOR
