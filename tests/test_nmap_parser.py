"""WT-96: the Nmap XML parser turns the lab fixtures into C1 scan results."""

import json
from pathlib import Path

import pytest

from watchtower.scanner.nmap_parser import _is_mac_randomised, parse_nmap_xml

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _without_scan_id(result: dict) -> dict:
    # scan_id is a fresh UUID on every parse, so it can't be compared.
    return {key: value for key, value in result.items() if key != "scan_id"}


@pytest.mark.parametrize("profile", ["quick", "full"])
def test_parse_matches_expected_c1(profile: str) -> None:
    result = parse_nmap_xml(FIXTURES / f"lab-{profile}.xml", profile=profile)
    expected = json.loads((FIXTURES / f"lab-{profile}.c1.json").read_text(encoding="utf-8"))
    assert _without_scan_id(result) == _without_scan_id(expected)


@pytest.mark.parametrize("profile", ["quick", "full"])
def test_profile_detected_from_nmap_args(profile: str) -> None:
    assert parse_nmap_xml(FIXTURES / f"lab-{profile}.xml")["profile"] == profile


def test_quick_scan_has_no_ports() -> None:
    result = parse_nmap_xml(FIXTURES / "lab-quick.xml")
    assert result["subnet"] == "172.28.0.0/24"
    assert all(host["ports"] == [] for host in result["hosts"])


def test_full_scan_finds_router_services() -> None:
    result = parse_nmap_xml(FIXTURES / "lab-full.xml")
    router = next(host for host in result["hosts"] if host["ip"] == "172.28.0.2")
    assert router["vendor"] == "TP-Link Technologies"
    assert [port["port"] for port in router["ports"]] == [53, 80, 5000]
    assert router["ports"][0]["product"] == "dnsmasq"


@pytest.mark.parametrize(
    ("mac", "randomised"),
    [("A2:FC:AE:A8:A0:A9", True), ("50:C7:BF:11:00:02", False), (None, False)],
)
def test_mac_randomised_flag(mac: str | None, randomised: bool) -> None:
    assert _is_mac_randomised(mac) is randomised


def test_rejects_non_nmap_xml(tmp_path: Path) -> None:
    not_nmap = tmp_path / "other.xml"
    not_nmap.write_text("<report/>", encoding="utf-8")
    with pytest.raises(ValueError, match="nmaprun"):
        parse_nmap_xml(not_nmap)
