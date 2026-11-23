"""The full profile scans Nmap's top 1000 TCP ports plus MQTT (WT-FR-10, TC-06, TC-10)."""

from pathlib import Path

import yaml

from watchtower.scanner.command_builder import build_command
from watchtower.scanner.ports import EXTRA_PORTS, FULL_SCAN_PORTS, TOP_1000_TCP, expand

ROOT = Path(__file__).resolve().parents[1]


def test_top_1000_has_exactly_1000_ports() -> None:
    assert len(expand(TOP_1000_TCP)) == 1000


def test_mqtt_is_added_because_top_1000_misses_it() -> None:
    assert 1883 not in expand(TOP_1000_TCP)
    assert {1883, 8883} <= expand(FULL_SCAN_PORTS)
    assert len(expand(FULL_SCAN_PORTS)) == 1000 + len(EXTRA_PORTS)


def test_every_lab_port_is_scanned() -> None:
    # TC-10: a rule only works if the full profile looks at its port.
    devices = yaml.safe_load((ROOT / "lab" / "inventory.yaml").read_text())["devices"]
    scanned = expand(FULL_SCAN_PORTS)
    for device in devices:
        missing = set(device["ports"]) - scanned
        assert not missing, f"{device['name']}: full profile never scans {sorted(missing)}"


def test_full_command_uses_the_list_not_top_ports() -> None:
    argv = build_command("full", "172.28.0.0/24", "172.28.0.20")
    assert argv[argv.index("-p") + 1] == FULL_SCAN_PORTS
    assert "--top-ports" not in argv
