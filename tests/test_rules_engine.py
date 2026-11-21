"""WT-65: the rules engine (TC-10). Run with: pytest tests/test_rules_engine.py -v"""

from pathlib import Path

import pytest
import yaml

from watchtower.analysis.rules import evaluate, load_rules
from watchtower.scanner.models import Host, Port, ScanResult

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def rules() -> list[dict]:
    return load_rules(ROOT / "rules" / "red_flags.yaml")


def make_host(*ports: int, service: str | None = None) -> Host:
    """A pretend device with these open TCP ports (all given the same service name)."""
    return Host(
        ip="172.28.0.99",
        mac="aa:bb:cc:dd:ee:ff",
        ports=[Port(port=n, protocol="tcp", state="open", service=service) for n in ports],
    )


def rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# ---- 1. The lab: every device gets exactly the findings inventory.yaml expects ----


def test_lab_full_scan_matches_inventory(rules):
    scan = ScanResult.from_json((ROOT / "tests/fixtures/lab-full.c1.json").read_text())
    inventory = yaml.safe_load((ROOT / "lab/inventory.yaml").read_text())["devices"]
    by_mac = {d["mac"].lower(): d for d in inventory}

    checked = 0
    for host in scan.hosts:
        device = by_mac.get((host.mac or "").lower())
        if device is None:
            continue  # the Docker gateway 172.28.0.1 is not a lab device
        got = rule_ids(evaluate(host, device["type"], rules))
        assert got == set(device["expected_findings"]), device["name"]
        checked += 1
    assert checked >= 4  # router, camera, laptop, nas


# ---- 2. Hand-made devices ----


def test_telnet_is_flagged(rules):
    assert rule_ids(evaluate(make_host(23), "camera", rules)) == {"RF-TELNET"}


def test_port_80_on_a_router_is_admin_page(rules):
    assert rule_ids(evaluate(make_host(80), "router", rules)) == {"RF-HTTP-ADMIN"}


def test_port_80_on_a_printer_is_not_admin_page(rules):
    assert rule_ids(evaluate(make_host(80), "printer", rules)) == {"RF-HTTP-PRINTER"}


def test_port_80_with_unknown_type_raises_nothing(rules):
    assert evaluate(make_host(80), None, rules) == []


@pytest.mark.parametrize(
    ("port", "rule_id"),
    [
        (21, "RF-FTP"),
        (445, "RF-SMB"),
        (1883, "RF-MQTT"),
        (3389, "RF-RDP"),
        (5900, "RF-VNC"),
        (5555, "RF-ADB"),
    ],
)
def test_each_port_rule(rules, port, rule_id):
    assert rule_ids(evaluate(make_host(port), None, rules)) == {rule_id}


def test_upnp_matches_by_service_name(rules):
    assert rule_ids(evaluate(make_host(5000, service="upnp"), "router", rules)) == {"RF-UPNP"}


def test_ssh_only_is_clean(rules):
    assert evaluate(make_host(22), "laptop", rules) == []


def test_no_open_ports_is_clean(rules):
    assert evaluate(make_host(), "phone", rules) == []


def test_finding_carries_rule_text_and_port(rules):
    [finding] = evaluate(make_host(23), "camera", rules)
    assert finding.severity == "high"
    assert finding.port == 23
    assert finding.title and finding.explanation and finding.fix


def test_version_below_rule_is_skipped_for_now():
    rule = {
        "id": "RF-TEST-OLD",
        "title": "t",
        "severity": "high",
        "explanation": "e",
        "fix": "f",
        "match": {"product": "vsftpd", "version_below": "3.0"},
    }
    host = Host(
        ip="172.28.0.99",
        ports=[Port(port=21, protocol="tcp", state="open", product="vsftpd", version="2.3.4")],
    )
    assert evaluate(host, None, [rule]) == []
