"""WT-102 (PRD T-17, milestone M2): `watchtower scan` runs the whole pipeline once."""

from pathlib import Path

import pytest
import yaml
from sqlalchemy import func, select

from watchtower.cli import main
from watchtower.pipeline import ScanError, format_report, rules_device_type, run_scan
from watchtower.scanner.models import TypeGuess
from watchtower.scanner.scan_engine import FakeEngine, ScanFailed
from watchtower.store import models as m
from watchtower.store.db import make_engine, make_sessionmaker

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
LAB = "172.28.0.0/24"
# Same temporary gap as tests/test_rules_engine.py: the saved scan has no port 1883.
PENDING = {("smart-plug", "RF-MQTT")}


def _rows(db: Path, model) -> list:
    engine = make_engine(db)
    try:
        with make_sessionmaker(engine)() as s:
            return list(s.scalars(select(model)))
    finally:
        engine.dispose()


def _count(db: Path, model) -> int:
    engine = make_engine(db)
    try:
        with make_sessionmaker(engine)() as s:
            return s.scalar(select(func.count()).select_from(model))
    finally:
        engine.dispose()


def test_full_scan_raises_every_planted_risk_and_nothing_else(tmp_path: Path) -> None:
    report = run_scan(FakeEngine(FIXTURES), "full", LAB, tmp_path / "w.db")
    inventory = yaml.safe_load((ROOT / "lab/inventory.yaml").read_text())["devices"]
    by_mac = {d["mac"]: d for d in inventory}
    seen = 0
    for device in report.devices:
        lab = by_mac.get((device.mac or "").lower())
        if lab is None:
            assert device.findings == []  # Docker's gateway
            continue
        expected = {r for r in lab["expected_findings"] if (lab["name"], r) not in PENDING}
        assert {f.rule_id for f in device.findings} == expected, lab["name"]
        assert device.guess.type == lab["type"], lab["name"]
        seen += 1
    assert seen == len(inventory)


def test_results_are_stored(tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    report = run_scan(FakeEngine(FIXTURES), "full", LAB, db)
    [scan] = _rows(db, m.Scan)
    assert (scan.id, scan.status, scan.profile, scan.trigger) == (
        report.scan_id,
        "done",
        "full",
        "request",
    )
    assert _count(db, m.Device) == len(report.devices)
    assert _count(db, m.Finding) == report.finding_count
    camera = next(d for d in _rows(db, m.Device) if d.type == "camera")
    assert camera.type_confidence == 1.0


def test_second_full_scan_keeps_one_open_row_per_finding(tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    first = run_scan(FakeEngine(FIXTURES), "full", LAB, db)
    run_scan(FakeEngine(FIXTURES), "full", LAB, db)
    rows = _rows(db, m.Finding)
    assert len(rows) == first.finding_count
    assert all(r.closed_at is None for r in rows)
    assert _count(db, m.Scan) == 2


def test_quick_scan_finds_devices_but_raises_no_findings(tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    report = run_scan(FakeEngine(FIXTURES), "quick", LAB, db)
    assert report.finding_count == 0
    assert _count(db, m.Device) == len(report.devices) == 10
    assert "Run a full scan" in format_report(report)


class _BrokenEngine:
    def run(self, profile: str, target: str):
        raise ScanFailed("full scan timed out after 1800 seconds")


def test_failed_scan_is_recorded_and_reported(tmp_path: Path) -> None:
    db = tmp_path / "w.db"
    with pytest.raises(ScanError, match="timed out"):
        run_scan(_BrokenEngine(), "full", LAB, db)
    [scan] = _rows(db, m.Scan)
    assert scan.status == "failed"
    assert "timed out" in scan.error
    assert _count(db, m.Device) == 0


@pytest.mark.parametrize(
    ("guess", "expected"),
    [
        (TypeGuess("router", 1.0, ["x"]), "router"),
        (TypeGuess("router", 0.67, ["x"]), "router"),
        (TypeGuess("router", 0.33, ["x"]), None),  # too unsure for device-type rules
        (TypeGuess("unknown", 0.0, []), None),
    ],
)
def test_rules_only_trust_a_confident_type(guess: TypeGuess, expected: str | None) -> None:
    assert rules_device_type(guess) == expected


def test_report_lists_worst_device_first(tmp_path: Path) -> None:
    report = run_scan(FakeEngine(FIXTURES), "full", LAB, tmp_path / "w.db")
    text = format_report(report)
    assert text.startswith(f"Watchtower scan {report.scan_id} (full) of {LAB}")
    assert report.devices[0].findings[0].severity == "high"
    assert "Fix: " in text


def test_cli_scan_with_saved_lab_scan(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["scan", "--fake", str(FIXTURES), "--db", str(tmp_path / "w.db")]) == 0
    out = capsys.readouterr().out
    assert "RF-TELNET" in out and "camera" in out


def test_cli_scan_refuses_without_config(tmp_path: Path) -> None:
    # No config means no interface, so no target: nothing is scanned.
    assert main(["scan", "--config", str(tmp_path / "missing.toml")]) == 2
    assert not (tmp_path / "w.db").exists()


def test_cli_scan_refuses_a_bad_interface(tmp_path: Path, monkeypatch) -> None:
    from watchtower.scanner import guardrail

    def public_scope(interface: str):
        return guardrail.scope_from_interface_address("8.8.8.8/24")  # not a private network

    monkeypatch.setattr(guardrail, "scan_scope", public_scope)
    cfg = tmp_path / "w.toml"
    cfg.write_text(
        'interface = "eth0"\ndb_path = "w.db"\nquick_interval_min = 5\n'
        'full_interval_min = 15\ndashboard_url = "http://localhost:8000"\n'
    )
    assert main(["scan", "--config", str(cfg), "--db", str(tmp_path / "w.db")]) == 2
