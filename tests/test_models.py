from datetime import UTC, datetime
from pathlib import Path

import pytest

from watchtower.scanner.models import Finding, Host, ModelError, Port, ScanResult, TypeGuess

REPO_ROOT = Path(__file__).resolve().parents[1]


def sample_scan() -> ScanResult:
    """A scan built only from lab values."""
    return ScanResult(
        scan_id="11111111-2222-4333-8444-555555555555",
        profile="full",
        subnet="172.30.0.0/24",
        started_at=datetime(2026, 11, 5, 17, 39, 27, tzinfo=UTC),
        finished_at=datetime(2026, 11, 5, 17, 39, 29, tzinfo=UTC),
        nmap_version="7.95",
        hosts=[
            Host(
                ip="172.30.0.3",
                mac="C0:56:E3:12:34:56",
                vendor="Hikvision",
                mac_randomised=False,
                hostname=None,
                ports=[
                    Port(23, "tcp", "open", "telnet", None, None),
                    Port(80, "tcp", "open", "http", "BusyBox httpd", None),
                ],
            ),
            Host(ip="172.30.0.4", mac="3A:7F:21:9C:44:B1", mac_randomised=True),
        ],
    )


def test_scan_result_round_trips_through_json() -> None:
    original = sample_scan()
    assert ScanResult.from_json(original.to_json()) == original


def test_quick_scan_with_no_ports_round_trips() -> None:
    quick = ScanResult(
        scan_id="abc",
        profile="quick",
        subnet="172.30.0.0/24",
        started_at=datetime(2026, 11, 5, tzinfo=UTC),
        finished_at=datetime(2026, 11, 5, tzinfo=UTC),
        nmap_version="7.95",
        hosts=[Host(ip="172.30.0.2")],
    )
    assert ScanResult.from_json(quick.to_json()) == quick


def test_type_guess_and_finding_round_trip() -> None:
    guess = TypeGuess("camera", 0.9, ["Hikvision MAC", "RTSP on 554"])
    finding = Finding(
        "RF-TELNET", "high", "Telnet is open", "Anyone can try to log in.", "Turn telnet off.", 23
    )
    assert TypeGuess.from_json(guess.to_json()) == guess
    assert Finding.from_json(finding.to_json()) == finding


def test_os_guess_defaults_to_none_and_round_trips() -> None:
    host = Host(ip="172.30.0.2")
    assert host.os_guess is None
    assert host.to_dict()["os_guess"] is None
    assert Host.from_json(host.to_json()) == host


def test_missing_key_fails_loudly() -> None:
    data = sample_scan().to_dict()
    del data["nmap_version"]
    with pytest.raises(ModelError, match="nmap_version"):
        ScanResult.from_dict(data)


def test_bad_profile_rejected() -> None:
    data = sample_scan().to_dict()
    data["profile"] = "deep"
    with pytest.raises(ModelError, match="profile"):
        ScanResult.from_dict(data)


@pytest.mark.parametrize("bad", ["high", 1.5, -0.1])
def test_bad_confidence_rejected(bad: object) -> None:
    with pytest.raises(ModelError, match="confidence"):
        TypeGuess("camera", bad, [])  # type: ignore[arg-type]
