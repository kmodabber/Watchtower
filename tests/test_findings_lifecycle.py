"""WT-66 (WT-FR-15, TC-10, decision D6): findings open, stay open and close with full scans."""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from watchtower.scanner.models import Finding, Host, Port, ScanResult
from watchtower.store import models as m
from watchtower.store.db import make_engine, make_sessionmaker, upgrade
from watchtower.store.storage import save_scan

CAMERA = "c0:56:e3:12:34:56"
LAPTOP = "3a:7f:21:9c:44:b1"
TELNET = Finding("RF-TELNET", "high", "Telnet is open", "Passwords in clear.", "Turn it off.", 23)
HTTP = Finding("RF-HTTP-ADMIN", "medium", "Admin page over HTTP", "Unencrypted.", "Use HTTPS.", 80)


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    upgrade(tmp_path / "w.db")
    engine = make_engine(tmp_path / "w.db")
    with make_sessionmaker(engine)() as s:
        yield s
    engine.dispose()


def _scan(hosts: list[Host], profile: str = "full", minute: int = 0) -> ScanResult:
    at = datetime(2026, 11, 22, 12, minute, tzinfo=UTC)
    return ScanResult("id", profile, "172.28.0.0/24", at, at, "7.95", hosts)


def _camera(*ports: int) -> Host:
    return Host(ip="172.28.0.3", mac=CAMERA, ports=[Port(p, "tcp", "open") for p in ports])


def _findings(session: Session) -> list[m.Finding]:
    return list(session.scalars(select(m.Finding).order_by(m.Finding.id)))


def _open(session: Session) -> set[str]:
    return {f.rule_id for f in _findings(session) if f.closed_at is None}


def test_full_scan_opens_findings(session: Session) -> None:
    save_scan(session, _scan([_camera(23, 80)]), findings={"172.28.0.3": [TELNET, HTTP]})
    rows = _findings(session)
    assert {r.rule_id for r in rows} == {"RF-TELNET", "RF-HTTP-ADMIN"}
    telnet = next(r for r in rows if r.rule_id == "RF-TELNET")
    assert (telnet.port, telnet.severity, telnet.first_seen) == (23, "high", "2026-11-22T12:00:00Z")
    assert telnet.closed_at is None


def test_finding_seen_again_stays_one_open_row(session: Session) -> None:
    save_scan(session, _scan([_camera(23)], minute=0), findings={"172.28.0.3": [TELNET]})
    save_scan(session, _scan([_camera(23)], minute=15), findings={"172.28.0.3": [TELNET]})
    [row] = _findings(session)
    assert row.first_seen == "2026-11-22T12:00:00Z"
    assert row.last_seen == "2026-11-22T12:15:00Z"
    assert row.closed_at is None


def test_finding_closes_when_a_full_scan_no_longer_sees_it(session: Session) -> None:
    save_scan(session, _scan([_camera(23, 80)], minute=0), findings={"172.28.0.3": [TELNET, HTTP]})
    save_scan(session, _scan([_camera(80)], minute=15), findings={"172.28.0.3": [HTTP]})
    telnet = next(r for r in _findings(session) if r.rule_id == "RF-TELNET")
    assert telnet.closed_at == "2026-11-22T12:15:00Z"
    assert _open(session) == {"RF-HTTP-ADMIN"}


def test_closed_finding_that_comes_back_opens_a_new_row(session: Session) -> None:
    save_scan(session, _scan([_camera(23)], minute=0), findings={"172.28.0.3": [TELNET]})
    save_scan(session, _scan([_camera()], minute=15), findings={"172.28.0.3": []})
    save_scan(session, _scan([_camera(23)], minute=30), findings={"172.28.0.3": [TELNET]})
    rows = _findings(session)
    assert len(rows) == 2
    assert rows[0].closed_at == "2026-11-22T12:15:00Z"
    assert rows[1].closed_at is None and rows[1].first_seen == "2026-11-22T12:30:00Z"


def test_quick_scan_never_touches_findings(session: Session) -> None:
    save_scan(session, _scan([_camera(23)]), findings={"172.28.0.3": [TELNET]})
    save_scan(session, _scan([_camera()], profile="quick", minute=5), findings={})
    assert _open(session) == {"RF-TELNET"}


def test_device_missing_from_a_full_scan_keeps_its_findings(session: Session) -> None:
    # Offline is not fixed: only a scan that sees the device without the risk closes it.
    save_scan(session, _scan([_camera(23)], minute=0), findings={"172.28.0.3": [TELNET]})
    laptop = Host(ip="172.28.0.4", mac=LAPTOP, ports=[Port(22, "tcp", "open")])
    save_scan(session, _scan([laptop], minute=15), findings={"172.28.0.4": []})
    assert _open(session) == {"RF-TELNET"}


def test_without_findings_argument_rules_are_left_alone(session: Session) -> None:
    save_scan(session, _scan([_camera(23)], minute=0), findings={"172.28.0.3": [TELNET]})
    save_scan(session, _scan([_camera()], minute=15))  # caller did not run the rules
    assert _open(session) == {"RF-TELNET"}


def test_clean_device_gets_no_findings(session: Session) -> None:
    laptop = Host(ip="172.28.0.4", mac=LAPTOP, ports=[Port(22, "tcp", "open")])
    save_scan(session, _scan([laptop]), findings={"172.28.0.4": []})
    assert _findings(session) == []
