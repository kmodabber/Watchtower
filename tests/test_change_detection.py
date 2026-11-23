"""WT-67 (WT-FR-16, PRD T-20, TC-12, decision D5): what changed since the last scan."""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from watchtower.pipeline import run_scan
from watchtower.scanner.models import Host, Port, ScanResult
from watchtower.scanner.scan_engine import FakeEngine
from watchtower.store import models as m
from watchtower.store.changes import detect_changes
from watchtower.store.db import make_engine, make_sessionmaker, upgrade
from watchtower.store.storage import save_scan

FIXTURES = Path(__file__).resolve().parent / "fixtures"
LAB = "172.28.0.0/24"
TV = "00:11:32:33:00:01"
PRINTER = "00:11:32:33:00:02"
LAPTOP = "00:11:32:33:00:03"
SERVICES = {23: "telnet", 80: "http", 631: "ipp"}
IPS = {TV: "172.28.0.10", PRINTER: "172.28.0.11", LAPTOP: "172.28.0.12"}


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    upgrade(tmp_path / "w.db")
    engine = make_engine(tmp_path / "w.db")
    with make_sessionmaker(engine)() as s:
        yield s
    engine.dispose()


def _scan(hosts: list[Host], profile: str = "full", minute: int = 0) -> ScanResult:
    at = datetime(2026, 11, 23, 12, minute, tzinfo=UTC)
    return ScanResult("id", profile, LAB, at, at, "7.95", hosts)


def _host(mac: str, *ports: int) -> Host:
    return Host(
        ip=IPS[mac],
        mac=mac,
        ports=[Port(p, "tcp", "open", SERVICES.get(p)) for p in ports],
    )


def _run(session: Session, hosts: list[Host], profile: str = "full", minute: int = 0) -> list[str]:
    """Save one scan, detect its changes and return their kinds."""
    scan = save_scan(session, _scan(hosts, profile, minute))
    return [c.kind for c in detect_changes(session, scan.id)]


def _quick(session: Session, minute: int, *macs: str) -> list[str]:
    return _run(session, [_host(mac) for mac in macs], "quick", minute)


def _failed(session: Session, profile: str, minute: int) -> None:
    at = f"2026-11-23T12:{minute:02d}:00Z"
    session.add(
        m.Scan(
            profile=profile,
            subnet=LAB,
            started_at=at,
            finished_at=at,
            status="failed",
            error="timed out",
        )
    )
    session.flush()


def _changes(session: Session) -> list[m.Change]:
    return list(session.scalars(select(m.Change).order_by(m.Change.id)))


def _device(session: Session, mac: str) -> m.Device:
    return session.scalars(select(m.Device).where(m.Device.mac == mac)).one()


def test_first_scan_is_a_baseline(session: Session) -> None:
    assert _run(session, [_host(TV, 80, 443), _host(PRINTER, 631), _host(LAPTOP)]) == []
    assert _changes(session) == []


def test_new_device_in_second_scan(session: Session) -> None:
    _run(session, [_host(TV, 80)], minute=0)
    assert _run(session, [_host(TV, 80), _host(LAPTOP, 22)], minute=15) == ["new_device"]
    [change] = _changes(session)
    assert change.device_id == _device(session, LAPTOP).id
    assert json.loads(change.detail) == {
        "ip": IPS[LAPTOP],
        "mac": LAPTOP,
        "hostname": None,
        "vendor": None,
    }


def test_new_device_found_by_a_quick_scan(session: Session) -> None:
    _run(session, [_host(TV)], minute=0)
    assert _quick(session, 5, TV, LAPTOP) == ["new_device"]


def test_scans_with_the_same_timestamp_do_not_repeat_new_device(session: Session) -> None:
    # A replayed saved scan has the same time, so first_seen equals this scan's time too.
    _run(session, [_host(TV, 80)], minute=0)
    assert _run(session, [_host(TV, 80)], minute=0) == []


def test_port_opened_between_full_scans(session: Session) -> None:
    _run(session, [_host(TV, 80)], minute=0)
    assert _run(session, [_host(TV, 80, 23)], minute=15) == ["new_port"]
    [change] = _changes(session)
    assert change.device_id == _device(session, TV).id
    assert json.loads(change.detail) == {"port": 23, "protocol": "tcp", "service": "telnet"}


def test_port_closed_between_full_scans(session: Session) -> None:
    _run(session, [_host(TV, 80, 23)], minute=0)
    assert _run(session, [_host(TV, 80)], minute=15) == ["port_closed"]
    [change] = _changes(session)
    assert json.loads(change.detail) == {"port": 23, "protocol": "tcp", "service": "telnet"}


def test_same_port_number_on_another_protocol_is_a_change(session: Session) -> None:
    _run(session, [_host(TV, 53)], minute=0)
    udp = Host(ip=IPS[TV], mac=TV, ports=[Port(53, "udp", "open")])
    assert sorted(_run(session, [udp], minute=15)) == ["new_port", "port_closed"]


def test_only_open_ports_are_compared(session: Session) -> None:
    _run(session, [_host(TV, 80)], minute=0)
    filtered = Host(
        ip=IPS[TV], mac=TV, ports=[Port(80, "tcp", "open"), Port(23, "tcp", "filtered")]
    )
    assert _run(session, [filtered], minute=15) == []


def test_device_first_full_scan_has_no_port_changes(session: Session) -> None:
    _quick(session, 0, TV)
    assert _run(session, [_host(TV, 80, 23)], minute=15) == []


def test_quick_scan_gives_no_port_changes_and_is_skipped(session: Session) -> None:
    _run(session, [_host(TV, 80)], minute=0)
    assert _quick(session, 5, TV) == []  # no port data, but nothing "closed"
    assert _run(session, [_host(TV, 80, 23)], minute=15) == ["new_port"]  # against minute 0


def test_full_scan_missing_a_device_uses_its_last_full_scan(session: Session) -> None:
    _run(session, [_host(TV, 80), _host(PRINTER, 631)], minute=0)
    _run(session, [_host(TV, 80)], minute=15)
    assert _run(session, [_host(TV, 80), _host(PRINTER, 631, 23)], minute=30) == ["new_port"]


def test_device_missing_for_three_quick_scans_is_gone_once(session: Session) -> None:
    _run(session, [_host(TV), _host(PRINTER)], minute=0)
    assert _quick(session, 5, TV) == []
    assert _quick(session, 10, TV) == []  # missing only 2: nothing yet
    assert _device(session, PRINTER).status == "online"
    assert _quick(session, 15, TV) == ["device_gone"]
    printer = _device(session, PRINTER)
    assert printer.status == "gone"
    [change] = _changes(session)
    assert change.device_id == printer.id
    assert json.loads(change.detail) == {
        "ip": IPS[PRINTER],
        "last_seen": "2026-11-23T12:00:00Z",
    }
    assert _quick(session, 20, TV) == []  # a 4th missing scan adds nothing
    assert len(_changes(session)) == 1


def test_device_seen_in_the_oldest_of_three_quick_scans_stays(session: Session) -> None:
    _run(session, [_host(TV), _host(PRINTER)], minute=0)
    _quick(session, 5, TV, PRINTER)
    _quick(session, 10, TV)
    assert _quick(session, 15, TV) == []
    assert _device(session, PRINTER).status == "online"


def test_full_scan_sighting_counts_as_presence(session: Session) -> None:
    _run(session, [_host(TV), _host(PRINTER)], minute=0)
    _quick(session, 5, TV)
    _quick(session, 10, TV)
    _run(session, [_host(TV), _host(PRINTER)], minute=12)
    assert _quick(session, 15, TV) == []
    assert _device(session, PRINTER).status == "online"


def test_gone_device_coming_back_is_not_new(session: Session) -> None:
    _run(session, [_host(TV), _host(PRINTER)], minute=0)
    for minute in (5, 10, 15):
        _quick(session, minute, TV)
    assert _device(session, PRINTER).status == "gone"
    assert _quick(session, 20, TV, PRINTER) == []
    assert _device(session, PRINTER).status == "online"


def test_failed_scan_does_not_end_the_baseline(session: Session) -> None:
    _failed(session, "full", 0)
    assert _run(session, [_host(TV, 80)], minute=5) == []


def test_failed_scans_do_not_count_as_quick_scans(session: Session) -> None:
    _run(session, [_host(TV), _host(PRINTER)], minute=0)
    _quick(session, 5, TV)
    _failed(session, "quick", 7)
    assert _quick(session, 10, TV) == []  # only 2 done quick scans so far
    assert _device(session, PRINTER).status == "online"
    assert _quick(session, 15, TV) == ["device_gone"]


def test_failed_full_scan_is_not_the_previous_full_scan(session: Session) -> None:
    _run(session, [_host(TV, 80)], minute=0)
    _failed(session, "full", 5)
    assert _run(session, [_host(TV, 80, 23)], minute=10) == ["new_port"]


def test_detect_changes_on_a_failed_scan_records_nothing(session: Session) -> None:
    _run(session, [_host(TV)], minute=0)
    _failed(session, "full", 5)
    failed_id = session.scalar(select(m.Scan.id).where(m.Scan.status == "failed"))
    assert detect_changes(session, failed_id) == []


def test_calling_twice_adds_no_duplicates(session: Session) -> None:
    _run(session, [_host(TV, 80)], minute=0)
    scan = save_scan(session, _scan([_host(TV, 80, 23), _host(LAPTOP)], minute=15))
    first = detect_changes(session, scan.id)
    second = detect_changes(session, scan.id)
    assert sorted(c.kind for c in first) == ["new_device", "new_port"]
    assert {c.id for c in second} == {c.id for c in first}
    assert len(_changes(session)) == 2


def test_tc12_combined_story(session: Session) -> None:
    _run(session, [_host(TV, 80), _host(PRINTER, 631)], minute=0)
    for minute in (5, 10, 15):
        _quick(session, minute, TV)  # the printer has stopped
    _run(session, [_host(TV, 80, 23), _host(LAPTOP, 22)], minute=20)

    got = {(c.kind, c.device_id) for c in _changes(session)}
    assert got == {
        ("device_gone", _device(session, PRINTER).id),
        ("new_device", _device(session, LAPTOP).id),
        ("new_port", _device(session, TV).id),
    }
    assert len(_changes(session)) == 3


class _SavedScans:
    """An engine that returns prepared results, one per run."""

    def __init__(self, *results: ScanResult) -> None:
        self.results = list(results)

    def run(self, profile: str, target: str) -> ScanResult:
        return self.results.pop(0)


def test_run_scan_records_changes(tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    engine = _SavedScans(
        _scan([_host(TV, 80)], minute=0),
        _scan([_host(TV, 80, 23), _host(LAPTOP)], minute=15),
    )
    assert run_scan(engine, "full", LAB, db, rules=[]).changes == []
    report = run_scan(engine, "full", LAB, db, rules=[])
    assert sorted(report.changes) == ["new_device", "new_port"]

    db_engine = make_engine(db)
    try:
        with make_sessionmaker(db_engine)() as s:
            rows = list(s.scalars(select(m.Change)))
            assert {c.scan_id for c in rows} == {report.scan_id}
            assert sorted(c.kind for c in rows) == ["new_device", "new_port"]
    finally:
        db_engine.dispose()


def test_replaying_the_same_saved_scan_reports_no_changes(tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    assert run_scan(FakeEngine(FIXTURES), "full", LAB, db).changes == []
    assert run_scan(FakeEngine(FIXTURES), "full", LAB, db).changes == []
