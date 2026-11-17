"""Device identification tests using recorded and synthetic scan data only."""

from pathlib import Path

import pytest
import yaml

from watchtower.scanner.identification import (
    CONFIDENCE_VALUES,
    confidence_label,
    identify_host,
    identify_scan,
    load_clues,
)
from watchtower.scanner.models import Host, Port, ScanResult, TypeGuess
from watchtower.scanner.nmap_parser import parse_nmap_xml

ROOT = Path(__file__).resolve().parents[1]
FULL_FIXTURE = ROOT / "tests" / "fixtures" / "lab-full-inventory.xml"
INVENTORY = ROOT / "lab" / "inventory.yaml"


def test_tc11_identifies_at_least_seven_inventory_devices_with_reasons() -> None:
    scan = ScanResult.from_dict(parse_nmap_xml(FULL_FIXTURE, profile="full"))
    guesses = identify_scan(scan)
    by_mac = {
        host.mac.lower(): guess for host, guess in zip(scan.hosts, guesses, strict=True) if host.mac
    }
    devices = yaml.safe_load(INVENTORY.read_text(encoding="utf-8"))["devices"]

    assert len(devices) == 8
    assert all(device["mac"] in by_mac for device in devices)

    correct = 0
    for device in devices:
        guess = by_mac[device["mac"]]
        assert isinstance(guess, TypeGuess)
        assert confidence_label(guess.confidence) in CONFIDENCE_VALUES
        assert guess.reasons, f"Missing reasons for {device['name']}"
        if guess.type == device["type"]:
            correct += 1

    assert correct >= 7, f"Only {correct}/8 inventoried devices correctly identified"


def test_camera_matches_vendor_and_rtsp_clues() -> None:
    camera = Host(
        ip="192.168.1.20",
        vendor="Hangzhou Hikvision Digital Technology",
        ports=[Port(554, "tcp", "open")],
    )
    guess = identify_host(camera)
    assert guess.type == "camera"
    assert guess.confidence == CONFIDENCE_VALUES["high"]
    assert guess.reasons == ["camera maker", "RTSP video port"]


def test_no_match_returns_unknown_without_reasons() -> None:
    host = Host(ip="192.168.1.20", vendor=None, hostname="mystery")
    guess = identify_host(host)
    assert guess == TypeGuess("unknown", CONFIDENCE_VALUES["unknown"], [])


def test_low_confidence_from_single_clue() -> None:
    guess = identify_host(Host(ip="192.168.1.20", vendor="Samsung Electronics"))
    assert guess.type == "smart-tv"
    assert guess.confidence == CONFIDENCE_VALUES["low"]
    assert guess.reasons == ["TV maker"]


def test_close_scores_lower_confidence_one_level() -> None:
    # Camera and printer each score 3, so medium drops to low.
    host = Host(
        ip="192.168.1.20",
        vendor="Hikvision",
        ports=[Port(9100, "tcp", "open")],
    )
    guess = identify_host(host)
    assert guess.type == "camera"  # stable YAML order when scores tie
    assert guess.confidence == CONFIDENCE_VALUES["low"]
    assert guess.reasons == ["camera maker"]


def test_one_point_difference_also_lowers_confidence() -> None:
    clues = [
        {"type": "camera", "points": 4, "hostname_contains": ["device"], "reason": "first"},
        {"type": "printer", "points": 3, "hostname_contains": ["device"], "reason": "second"},
    ]
    guess = identify_host(Host(ip="192.168.1.20", hostname="device"), clues=clues)
    assert guess.type == "camera"
    assert guess.confidence == CONFIDENCE_VALUES["low"]
    assert guess.reasons == ["first"]


def test_low_tie_cannot_downgrade_below_unknown() -> None:
    clues = [
        {"type": "camera", "points": 1, "hostname_contains": "device", "reason": "first"},
        {"type": "printer", "points": 1, "hostname_contains": "device", "reason": "second"},
    ]
    guess = identify_host(Host(ip="192.168.1.20", hostname="device"), clues=clues)
    assert guess.type == "camera"  # the winner is still known
    assert guess.confidence == CONFIDENCE_VALUES["unknown"]
    assert guess.reasons == ["first"]


def test_quick_scan_does_not_treat_missing_ports_as_confirmed_closed() -> None:
    host = Host(ip="192.168.1.22", mac="a6:5e:90:3d:71:c8")
    assert identify_host(host, profile="full").type == "phone"
    provisional = identify_host(host, profile="quick")
    assert provisional.type == "unknown"
    assert provisional.confidence == CONFIDENCE_VALUES["unknown"]


def test_private_mac_is_detected_using_shared_mac_helper() -> None:
    # Does not require the ScanEngine to have applied MAC labels yet.
    host = Host(
        ip="192.168.1.22",
        mac="3A-7F-21-9C-44-B1",
        mac_randomised=False,
        ports=[Port(22, "tcp", "open")],
    )
    guess = identify_host(host)
    assert guess.type == "laptop"
    assert guess.confidence == CONFIDENCE_VALUES["medium"]


def test_ignores_os_guess_and_closed_ports() -> None:
    host = Host(
        ip="192.168.1.22",
        os_guess="Camera",
        ports=[Port(554, "tcp", "closed")],
    )
    assert identify_host(host).type == "unknown"


def test_does_not_mutate_host_or_scan() -> None:
    scan = ScanResult.from_dict(parse_nmap_xml(FULL_FIXTURE, profile="full"))
    original = scan.to_dict()
    assert len(identify_scan(scan)) == len(scan.hosts)
    assert scan.to_dict() == original


@pytest.mark.parametrize("value", [0.0, 0.33, 0.67, 1.0])
def test_numeric_codes_convert_back_to_labels(value: float) -> None:
    assert CONFIDENCE_VALUES[confidence_label(value)] == value


def test_rejects_unsupported_confidence_code() -> None:
    with pytest.raises(ValueError, match="Unknown device confidence code"):
        confidence_label(0.91)


def test_rejects_unknown_scan_profile() -> None:
    with pytest.raises(ValueError, match="Invalid scan profile"):
        identify_host(Host(ip="192.168.1.1"), profile="other")


@pytest.mark.parametrize(
    "rules",
    [
        [],
        [{"type": "camera", "points": 3, "reason": "camera maker"}],
        [{"type": "camera", "points": 3, "reason": "camera maker", "os_guess": "camera"}],
        [{"type": "camera", "points": -1, "reason": "camera maker", "port": 554}],
    ],
)
def test_rejects_invalid_clue_files(tmp_path: Path, rules: list[dict]) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(yaml.safe_dump(rules), encoding="utf-8")
    with pytest.raises(ValueError, match="clues|Clue"):
        load_clues(path)
