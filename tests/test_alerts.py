"""WT-68 (WT-FR-17, PRD T-22, C5, TC-13): one Discord message for changes and high risks.

No test makes a network call: the sender is a fake, or httpx.post is patched.
"""

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from watchtower.alerts.alerts import send_alerts
from watchtower.alerts.discord import MAX_LENGTH
from watchtower.cli import main
from watchtower.pipeline import run_scan
from watchtower.scanner.models import Finding, Host, Port, ScanResult
from watchtower.store import models as m
from watchtower.store.changes import detect_changes
from watchtower.store.db import make_engine, make_sessionmaker, upgrade
from watchtower.store.storage import save_scan

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SUBNET = "192.168.8.0/24"
WEBHOOK = "https://discord.test/api/webhooks/123/not-a-real-token"
DASHBOARD = "http://watchtower.local:8000/"
CAMERA = "00:11:32:33:00:01"
PRINTER = "00:11:32:33:00:02"
LAPTOP = "00:11:32:33:00:03"
PHONE = "02:11:32:33:00:04"  # locally administered: a private address
IPS = {
    CAMERA: "192.168.8.10",
    PRINTER: "192.168.8.11",
    LAPTOP: "192.168.8.12",
    PHONE: "192.168.8.57",
}
SERVICES = {23: "telnet", 80: "http", 631: "ipp"}
TELNET = Finding("RF-TELNET", "high", "Telnet is open", "Readable.", "Turn it off.", 23)


class _Sender:
    """A fake send(): records each message and succeeds or fails on demand."""

    def __init__(self, ok: bool = True) -> None:
        self.ok = ok
        self.messages: list[str] = []

    def __call__(self, webhook_url: str, text: str) -> bool:
        assert webhook_url == WEBHOOK
        self.messages.append(text)
        return self.ok


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    upgrade(tmp_path / "w.db")
    engine = make_engine(tmp_path / "w.db")
    with make_sessionmaker(engine)() as s:
        yield s
    engine.dispose()


def _scan(hosts: list[Host], profile: str = "full", minute: int = 0) -> ScanResult:
    at = datetime(2026, 11, 23, 12, minute, tzinfo=UTC)
    return ScanResult("id", profile, SUBNET, at, at, "7.95", hosts)


def _host(mac: str, *ports: int, hostname: str | None = None, vendor: str | None = None) -> Host:
    return Host(
        ip=IPS[mac],
        mac=mac,
        hostname=hostname,
        vendor=vendor,
        ports=[Port(p, "tcp", "open", SERVICES.get(p)) for p in ports],
    )


def _save(
    session: Session,
    hosts: list[Host],
    minute: int,
    profile: str = "full",
    findings: dict[str, list[Finding]] | None = None,
) -> int:
    scan = save_scan(session, _scan(hosts, profile, minute), findings=findings or {})
    detect_changes(session, scan.id)
    return scan.id


def _step(
    session: Session,
    sender: _Sender,
    hosts: list[Host],
    minute: int,
    profile: str = "full",
    findings: dict[str, list[Finding]] | None = None,
) -> bool:
    """Save one scan, detect its changes and run the alerts step."""
    scan_id = _save(session, hosts, minute, profile, findings)
    return send_alerts(session, scan_id, WEBHOOK, DASHBOARD, sender=sender)


def _changes(session: Session) -> list[m.Change]:
    return list(session.scalars(select(m.Change).order_by(m.Change.id)))


def _device(session: Session, mac: str) -> m.Device:
    return session.scalars(select(m.Device).where(m.Device.mac == mac)).one()


def _mute(session: Session, mac: str) -> None:
    _device(session, mac).muted = True
    session.flush()


def test_baseline_scan_sends_nothing(session: Session) -> None:
    sender = _Sender()
    hosts = [_host(CAMERA, 23), _host(PRINTER, 631)]
    assert _step(session, sender, hosts, 0, findings={IPS[CAMERA]: [TELNET]}) is True
    assert sender.messages == []
    assert _changes(session) == []  # no new_finding on the baseline (D5)


def test_quiet_scan_sends_nothing(session: Session) -> None:
    sender = _Sender()
    findings = {IPS[CAMERA]: [TELNET]}
    _step(session, sender, [_host(CAMERA, 23)], 0, findings=findings)
    assert _step(session, sender, [_host(CAMERA, 23)], 15, findings=findings) is True
    assert sender.messages == []


def test_new_device_gives_one_message_and_is_marked(session: Session) -> None:
    sender = _Sender()
    _step(session, sender, [_host(CAMERA)], 0)
    _step(session, sender, [_host(CAMERA), _host(PHONE, hostname="Phone")], 15)
    assert sender.messages == [
        "Watchtower: 1 change on 192.168.8.0/24\n"
        "NEW DEVICE   Phone (private address), 192.168.8.57\n"
        "Details: http://watchtower.local:8000/changes"
    ]
    [change] = _changes(session)
    assert change.alerted_at is not None


def test_new_high_finding_is_listed_with_its_fix(session: Session) -> None:
    sender = _Sender()
    camera = _host(CAMERA, 80, hostname="Camera", vendor="Hikvision")
    _step(session, sender, [camera], 0)
    opened = _host(CAMERA, 80, 23, hostname="Camera", vendor="Hikvision")
    _step(session, sender, [opened], 15, findings={IPS[CAMERA]: [TELNET]})
    [message] = sender.messages
    assert message.split("\n")[1:3] == [
        "HIGH RISK    Camera (Hikvision), port 23: Telnet is open. What to do: Turn it off.",
        "NEW SERVICE  Camera (Hikvision), port 23 telnet",
    ]
    assert message.startswith("Watchtower: 2 changes on ")
    row = next(c for c in _changes(session) if c.kind == "new_finding")
    assert json.loads(row.detail) == {
        "rule_id": "RF-TELNET",
        "port": 23,
        "title": "Telnet is open",
        "severity": "high",
        "fix": "Turn it off.",
    }


@pytest.mark.parametrize("severity", ["medium", "low", "info"])
def test_lesser_new_findings_are_not_alerted(session: Session, severity: str) -> None:
    sender = _Sender()
    _step(session, sender, [_host(CAMERA, 80)], 0)
    minor = Finding("RF-MINOR", severity, "Minor", "Why.", "Fix.", 80)
    _step(session, sender, [_host(CAMERA, 80)], 15, findings={IPS[CAMERA]: [minor]})
    assert sender.messages == []
    assert _changes(session) == []


def test_replayed_scan_with_the_same_time_does_not_alert_old_findings(session: Session) -> None:
    sender = _Sender()
    findings = {IPS[CAMERA]: [TELNET]}
    _step(session, sender, [_host(CAMERA, 23)], 0, findings=findings)
    _step(session, sender, [_host(CAMERA, 23)], 0, findings=findings)
    assert sender.messages == []
    assert _changes(session) == []


def test_a_finding_gets_only_one_change(session: Session) -> None:
    sender = _Sender()
    _step(session, sender, [_host(CAMERA, 80)], 0)
    scan_id = _save(session, [_host(CAMERA, 80)], 15, findings={IPS[CAMERA]: [TELNET]})
    send_alerts(session, scan_id, WEBHOOK, DASHBOARD, sender=sender)
    send_alerts(session, scan_id, WEBHOOK, DASHBOARD, sender=sender)
    assert len(sender.messages) == 1
    assert [c.kind for c in _changes(session)] == ["new_finding"]


def test_muted_devices_are_skipped(session: Session) -> None:
    sender = _Sender()
    _step(session, sender, [_host(CAMERA, 80), _host(PRINTER, 631)], 0)
    _mute(session, CAMERA)
    hosts = [_host(CAMERA, 80, 23), _host(PRINTER, 631, 80)]
    _step(session, sender, hosts, 15, findings={IPS[CAMERA]: [TELNET]})
    [message] = sender.messages
    assert "port 80 http" in message and "port 23" not in message
    assert "new_finding" not in {c.kind for c in _changes(session)}
    muted = [c for c in _changes(session) if c.device_id == _device(session, CAMERA).id]
    assert [c.alerted_at for c in muted] == [None]


def test_failed_send_is_retried_with_new_changes_exactly_once(session: Session) -> None:
    sender = _Sender(ok=False)
    _step(session, sender, [_host(CAMERA)], 0)
    assert _step(session, sender, [_host(CAMERA), _host(LAPTOP, hostname="Laptop")], 15) is False
    assert [c.alerted_at for c in _changes(session)] == [None]

    sender.ok = True
    hosts = [_host(CAMERA), _host(LAPTOP, hostname="Laptop"), _host(PHONE, hostname="Phone")]
    assert _step(session, sender, hosts, 30) is True
    assert len(sender.messages) == 2
    last = sender.messages[-1]
    assert last.startswith("Watchtower: 2 changes")
    assert last.count("Laptop") == 1 and last.count("Phone,") + last.count("Phone (") == 1
    assert all(c.alerted_at for c in _changes(session))

    _step(session, sender, hosts, 45)
    assert len(sender.messages) == 2  # nothing is sent again after a success


def test_failed_high_finding_is_retried_on_a_later_scan(session: Session) -> None:
    sender = _Sender(ok=False)
    findings = {IPS[CAMERA]: [TELNET]}
    _step(session, sender, [_host(CAMERA, 23)], 0)
    _step(session, sender, [_host(CAMERA, 23)], 15, findings=findings)
    sender.ok = True
    _step(session, sender, [_host(CAMERA, 23)], 30, findings=findings)
    assert "HIGH RISK" in sender.messages[-1]
    assert len([c for c in _changes(session) if c.kind == "new_finding"]) == 1


def test_empty_webhook_logs_and_marks_delivered(
    session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    _save(session, [_host(CAMERA)], 0)
    scan_id = _save(session, [_host(CAMERA), _host(LAPTOP, hostname="Laptop")], 15)

    def no_send(_url: str, _text: str) -> bool:
        raise AssertionError("must not send without a webhook")

    assert send_alerts(session, scan_id, "", DASHBOARD, sender=no_send) is True
    assert "NEW DEVICE   Laptop" in caplog.text
    assert all(c.alerted_at for c in _changes(session))


def test_order_is_worst_first(session: Session) -> None:
    sender = _Sender(ok=False)
    _save(session, [_host(CAMERA, 80, 631), _host(PRINTER)], 0)
    for minute in (5, 10, 15):
        _save(session, [_host(CAMERA)], minute, "quick")
    hosts = [_host(CAMERA, 80, 23), _host(LAPTOP)]
    _step(session, sender, hosts, 20, findings={IPS[CAMERA]: [TELNET]})
    labels = [line[:11].strip() for line in sender.messages[0].split("\n")[1:-1]]
    assert labels == ["HIGH RISK", "NEW DEVICE", "NEW SERVICE", "PORT CLOSED", "DEVICE GONE"]


def test_long_message_fits_and_every_change_is_marked(session: Session) -> None:
    sender = _Sender()
    _step(session, sender, [_host(CAMERA)], 0)
    many = [
        Host(ip=f"192.168.8.{i}", mac=f"00:11:32:33:01:{i:02x}", hostname=f"device-{i}-" + "x" * 60)
        for i in range(20, 80)
    ]
    _step(session, sender, [_host(CAMERA), *many], 15)
    [message] = sender.messages
    lines = message.split("\n")
    assert len(message) <= MAX_LENGTH
    assert lines[0].startswith("Watchtower: 60 changes")
    assert lines[-1] == "Details: http://watchtower.local:8000/changes"
    assert lines[-2] == f"…and {60 - (len(lines) - 3)} more"
    assert all(c.alerted_at for c in _changes(session))


def test_hostile_hostname_cannot_ping_or_add_lines(session: Session) -> None:
    sender = _Sender()
    _step(session, sender, [_host(CAMERA)], 0)
    evil = _host(LAPTOP, hostname="@everyone\nHIGH RISK [click](http://evil.test)")
    _step(session, sender, [_host(CAMERA), evil], 15)
    [message] = sender.messages
    assert "@everyone" not in message
    assert "\\[click]" in message  # escaped, so Discord shows it as text and not a link
    assert len(message.split("\n")) == 3


def test_seeded_rows_without_detail_do_not_break_alerts(session: Session) -> None:
    sender = _Sender()
    scan_id = _save(session, [_host(CAMERA, 23)], 0)
    device_id = _device(session, CAMERA).id
    session.add(m.Change(scan_id=scan_id, device_id=device_id, kind="new_device"))
    detail = json.dumps({"rule_id": "RF-TELNET", "port": 23})
    session.add(m.Change(scan_id=scan_id, device_id=device_id, kind="new_finding", detail=detail))
    session.flush()
    assert send_alerts(session, scan_id, WEBHOOK, DASHBOARD, sender=sender) is True
    assert "HIGH RISK    Unknown device, port 23: RF-TELNET." in sender.messages[0]
    assert "NEW DEVICE   Unknown device, 192.168.8.10" in sender.messages[0]


def test_tc13_changes_give_one_message_then_quiet_scan_gives_none(session: Session) -> None:
    sender = _Sender()
    _save(session, [_host(CAMERA, 80), _host(PRINTER, 631)], 0)
    for minute in (5, 10, 15):
        _save(session, [_host(CAMERA)], minute, "quick")  # the printer has stopped
    hosts = [_host(CAMERA, 80, 23), _host(LAPTOP)]
    findings = {IPS[CAMERA]: [TELNET]}
    _step(session, sender, hosts, 20, findings=findings)

    [message] = sender.messages
    assert message.startswith("Watchtower: 4 changes on 192.168.8.0/24")
    for label in ("HIGH RISK", "NEW DEVICE", "NEW SERVICE", "DEVICE GONE"):
        assert message.count(label) == 1

    _step(session, sender, hosts, 25, findings=findings)
    assert len(sender.messages) == 1


class _SavedScans:
    """An engine that returns prepared results, one per run."""

    def __init__(self, *results: ScanResult) -> None:
        self.results = list(results)

    def run(self, profile: str, target: str) -> ScanResult:
        return self.results.pop(0)


def _two_scans() -> _SavedScans:
    return _SavedScans(
        _scan([_host(CAMERA)], minute=0),
        _scan([_host(CAMERA), _host(LAPTOP, hostname="Laptop")], minute=15),
    )


def _count_committed(db: Path) -> int:
    engine = make_engine(db)
    try:
        with make_sessionmaker(engine)() as s:
            return s.scalar(select(func.count()).select_from(m.Change))
    finally:
        engine.dispose()


def test_run_scan_sends_after_the_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "w.db"
    committed: list[int] = []

    def post(url: str, **kwargs: object) -> httpx.Response:
        assert url == WEBHOOK
        committed.append(_count_committed(db))  # a second connection sees the saved change
        return httpx.Response(204)

    monkeypatch.setattr(httpx, "post", post)
    engine = _two_scans()
    urls = {"webhook_url": WEBHOOK, "dashboard_url": DASHBOARD}
    assert run_scan(engine, "full", SUBNET, db, rules=[], **urls).alerted is True
    assert committed == []
    assert run_scan(engine, "full", SUBNET, db, rules=[], **urls).alerted is True
    assert committed == [1]


def test_alert_problem_does_not_fail_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("alerts are broken")

    monkeypatch.setattr("watchtower.pipeline.send_alerts", broken)
    report = run_scan(_two_scans(), "full", SUBNET, tmp_path / "w.db", rules=[])
    assert report.alerted is False
    assert report.scan_id == 1


def test_cli_fake_scan_never_touches_the_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(*_args: object, **_kwargs: object) -> httpx.Response:
        raise AssertionError("--fake must not send anything")

    monkeypatch.setattr(httpx, "post", no_network)
    args = ["scan", "--fake", str(FIXTURES), "--db", str(tmp_path / "w.db")]
    assert main(args) == 0
    assert main(args) == 0
