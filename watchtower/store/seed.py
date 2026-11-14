"""Fill a dev database with realistic rows so the API and dashboard can be built
before real scans are stored (WT-73).

Loads the saved lab scans in tests/fixtures (quick, then full), takes device types and
expected findings from lab/inventory.yaml and the finding text from rules/red_flags.yaml.

shortcut: reads the C1 fixtures directly; switch to FakeEngine + the real store (T-16/T-18)
once they exist.
"""

import json
from pathlib import Path

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from watchtower.scanner.models import ScanResult
from watchtower.store.db import make_engine, make_sessionmaker, upgrade
from watchtower.store.models import Change, Device, Finding, Port, Scan, Score, Sighting

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = [ROOT / "tests/fixtures/lab-quick.c1.json", ROOT / "tests/fixtures/lab-full.c1.json"]
# shortcut: made-up weights so /api/scores has data; replace with the WT-70 formula.
WEIGHTS = {"high": 40, "medium": 20, "low": 5, "info": 0}


class SeedError(Exception):
    pass


def _ts(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _store(session: Session, result: ScanResult, inventory: dict, rules: dict) -> Scan:
    at = _ts(result.finished_at)
    scan = Scan(
        profile=result.profile,
        subnet=result.subnet,
        nmap_version=result.nmap_version,
        started_at=_ts(result.started_at),
        finished_at=at,
        status="done",
    )
    session.add(scan)
    session.flush()
    for host in result.hosts:
        if not host.mac:
            continue
        mac = host.mac.lower()
        inv = inventory.get(mac, {})
        device = session.scalar(select(Device).where(Device.mac == mac))
        if device is None:
            device = Device(mac=mac, first_seen=at, last_seen=at)
            session.add(device)
            session.flush()
            session.add(Change(scan_id=scan.id, device_id=device.id, kind="new_device"))
        device.mac_randomised = host.mac_randomised
        device.vendor = host.vendor
        device.ip = host.ip
        device.hostname = host.hostname
        device.last_seen = at
        if inv:
            device.type = inv["type"]
            device.type_confidence = 0.9
            device.type_reasons = json.dumps([f"matches the lab inventory entry '{inv['name']}'"])
        session.add(Sighting(scan_id=scan.id, device_id=device.id, ip=host.ip))
        for p in host.ports:
            session.add(
                Port(
                    scan_id=scan.id,
                    device_id=device.id,
                    port=p.port,
                    protocol=p.protocol,
                    state=p.state,
                    service=p.service,
                    product=p.product,
                    version=p.version,
                )
            )
        if result.profile != "full":
            continue
        for rule_id in inv.get("expected_findings") or []:
            rule = rules[rule_id]
            match = rule["match"]
            port = match.get("port")
            if port is None:  # service rule: use the port that runs that service
                port = next((p.port for p in host.ports if p.service == match["service"]), None)
            session.add(
                Finding(
                    device_id=device.id,
                    rule_id=rule_id,
                    port=port,
                    severity=rule["severity"],
                    title=rule["title"],
                    explanation=" ".join(rule["explanation"].split()),
                    fix=" ".join(rule["fix"].split()),
                    first_seen=at,
                    last_seen=at,
                )
            )
            session.add(
                Change(
                    scan_id=scan.id,
                    device_id=device.id,
                    kind="new_finding",
                    detail=json.dumps({"rule_id": rule_id, "port": port}),
                )
            )
    session.flush()
    return scan


def _score(session: Session, scan: Scan) -> None:
    device_scores = []
    for device in session.scalars(select(Device)):
        severities = session.scalars(
            select(Finding.severity).where(
                Finding.device_id == device.id, Finding.closed_at.is_(None)
            )
        )
        score = min(100, sum(WEIGHTS[s] for s in severities))
        device_scores.append(score)
        session.add(Score(scan_id=scan.id, device_id=device.id, score=score))
    session.add(Score(scan_id=scan.id, device_id=None, score=max(device_scores, default=0)))


def seed(db_path: str | Path) -> int:
    """Create (or migrate) db_path and fill it. Refuses a database that already has scans."""
    upgrade(db_path)
    inventory = {
        d["mac"]: d for d in yaml.safe_load((ROOT / "lab/inventory.yaml").read_text())["devices"]
    }
    rules = {r["id"]: r for r in yaml.safe_load((ROOT / "rules/red_flags.yaml").read_text())}
    engine = make_engine(db_path)
    try:
        with make_sessionmaker(engine).begin() as session:
            if session.scalar(select(func.count()).select_from(Scan)):
                raise SeedError(f"{db_path} already has scans; delete it to re-seed.")
            for fixture in FIXTURES:
                scan = _store(session, ScanResult.from_json(fixture.read_text()), inventory, rules)
            _score(session, scan)
            return session.scalar(select(func.count()).select_from(Device))
    finally:
        engine.dispose()
