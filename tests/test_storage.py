"""WT-58 (WT-FR-07, TC-05): a device is remembered across scans (decision D7)."""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from watchtower.scanner.mac_helpers import PRIVATE_ADDRESS_VENDOR
from watchtower.scanner.models import Host, Port, ScanResult, TypeGuess
from watchtower.scanner.nmap_parser import parse_nmap_xml
from watchtower.store import models as m
from watchtower.store.db import make_engine, make_sessionmaker, upgrade
from watchtower.store.storage import save_scan

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CAMERA = "C0:56:E3:12:34:56"  # Nmap prints MACs upper case
PHONE_1, PHONE_2 = "a6:5e:90:3d:71:c8", "ba:11:22:33:44:55"  # randomised (LA bit set)


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    upgrade(tmp_path / "w.db")
    engine = make_engine(tmp_path / "w.db")
    with make_sessionmaker(engine)() as s:
        yield s
    engine.dispose()


def _scan(hosts: list[Host], profile: str = "full", minute: int = 0) -> ScanResult:
    at = datetime(2026, 11, 14, 12, minute, tzinfo=UTC)
    return ScanResult("id", profile, "172.28.0.0/24", at, at, "7.95", hosts)


def _host(mac: str | None, ip: str = "172.28.0.3", hostname: str | None = None, ports=()) -> Host:
    return Host(ip=ip, mac=mac, hostname=hostname, ports=[Port(p, "tcp", "open") for p in ports])


def _count(session: Session, model) -> int:
    return session.scalar(select(func.count()).select_from(model))


def _device(session: Session) -> m.Device:
    return session.scalars(select(m.Device)).one()


def test_same_device_kept_and_last_seen_updated(session: Session) -> None:
    save_scan(session, _scan([_host(CAMERA)], minute=0))
    save_scan(session, _scan([_host(CAMERA, ip="172.28.0.33")], minute=15))
    device = _device(session)
    assert device.mac == "c0:56:e3:12:34:56"  # stored in C2 form
    assert device.first_seen == "2026-11-14T12:00:00Z"
    assert device.last_seen == "2026-11-14T12:15:00Z"
    assert device.ip == "172.28.0.33"
    assert _count(session, m.Scan) == 2
    assert _count(session, m.Sighting) == 2


def test_randomised_mac_matched_by_hostname(session: Session) -> None:
    save_scan(session, _scan([_host(PHONE_1, hostname="adams-iphone")], minute=0))
    save_scan(session, _scan([_host(PHONE_2, hostname="adams-iphone")], minute=15))
    device = _device(session)
    assert device.mac == PHONE_2  # follows the new MAC, so the next scan matches by MAC
    assert device.first_seen == "2026-11-14T12:00:00Z"
    assert device.mac_randomised and device.vendor == PRIVATE_ADDRESS_VENDOR


def test_randomised_mac_without_hostname_is_a_new_device(session: Session) -> None:
    save_scan(session, _scan([_host(PHONE_1)], minute=0))
    save_scan(session, _scan([_host(PHONE_2)], minute=15))
    assert _count(session, m.Device) == 2


def test_real_mac_is_never_matched_by_hostname(session: Session) -> None:
    save_scan(session, _scan([_host(CAMERA, hostname="cam")], minute=0))
    save_scan(session, _scan([_host("00:11:32:33:00:04", hostname="cam")], minute=15))
    assert _count(session, m.Device) == 2


def test_two_phones_with_the_same_hostname_in_one_scan(session: Session) -> None:
    save_scan(session, _scan([_host(PHONE_1, hostname="iphone")], minute=0))
    hosts = [
        _host(PHONE_2, "172.28.0.30", "iphone"),
        _host("be:00:00:00:00:01", "172.28.0.31", "iphone"),
    ]
    save_scan(session, _scan(hosts, minute=15))
    assert _count(session, m.Device) == 2  # one matched by hostname, the other is new


def test_host_without_mac_is_skipped(session: Session) -> None:
    # Nmap can't see the scanner's own MAC; without a MAC there is nothing to recognise it by.
    scan = save_scan(session, _scan([_host(None), _host(CAMERA)]))
    assert _count(session, m.Device) == 1
    assert scan.status == "done"


def test_ports_stored_on_full_scans_only_and_never_deleted(session: Session) -> None:
    save_scan(session, _scan([_host(CAMERA, ports=(23, 80))], minute=0))
    save_scan(session, _scan([_host(CAMERA)], profile="quick", minute=5))
    assert sorted(session.scalars(select(m.Port.port))) == [23, 80]


def test_device_marked_online_again(session: Session) -> None:
    save_scan(session, _scan([_host(CAMERA)], minute=0))
    _device(session).status = "gone"
    save_scan(session, _scan([_host(CAMERA)], minute=15))
    assert _device(session).status == "online"


def test_type_guess_applied_on_full_scans_only(session: Session) -> None:
    guess = {"172.28.0.3": TypeGuess("camera", 0.9, ["camera maker"])}
    save_scan(session, _scan([_host(CAMERA)], profile="quick"), guess)
    assert _device(session).type is None
    save_scan(session, _scan([_host(CAMERA)], minute=15), guess)
    device = _device(session)
    assert (device.type, device.type_confidence, device.type_reasons) == (
        "camera",
        0.9,
        '["camera maker"]',
    )


def test_lab_scans_twice_keep_the_same_devices(session: Session) -> None:
    for profile in ("quick", "full", "quick", "full"):
        result = ScanResult.from_dict(parse_nmap_xml(FIXTURES / f"lab-{profile}.xml"))
        save_scan(session, result)
    # 9 lab devices plus Docker's gateway (172.28.0.1), which also answers scans.
    assert _count(session, m.Device) == 10
    assert _count(session, m.Scan) == 4


def test_same_mac_on_two_ips_is_saved_once(session: Session) -> None:
    # A router or NAS with a second address answers twice with the same MAC.
    hosts = [
        _host(CAMERA, ip="172.28.0.3", ports=[80]),
        _host(CAMERA, ip="172.28.0.33", ports=[80]),
    ]
    save_scan(session, _scan(hosts))
    assert _count(session, m.Device) == 1
    assert _count(session, m.Sighting) == 1
    assert _count(session, m.Port) == 1
    assert _device(session).ip == "172.28.0.3"  # the first address is kept
