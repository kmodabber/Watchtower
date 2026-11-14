"""The web service: read API for the dashboard, contract C4 (WT-FR-22, WT-73).

It only reads the database, plus three small writes: Scan now requests, the ownership
confirmation and (later, WT-82) device labels. It never imports the scan engine and never
runs Nmap. Browse http://127.0.0.1:8000/docs to try every endpoint.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import case, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from watchtower.store.db import DEFAULT_DB_PATH, make_engine, make_sessionmaker
from watchtower.store.models import (
    SEVERITIES,
    Change,
    Device,
    Finding,
    Port,
    Scan,
    ScanRequest,
    Score,
    Setting,
    utcnow,
)

Severity = Literal["high", "medium", "low", "info"]
Profile = Literal["quick", "full"]
WORST_FIRST = case({s: i for i, s in enumerate(SEVERITIES)}, value=Finding.severity)


# ---- Response and request models -------------------------------------------------------


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class HealthOut(Out):
    status: Literal["ok"] = "ok"
    database_ok: bool
    last_scan_at: str | None
    ownership_confirmed: bool


class DeviceOut(Out):
    id: int
    name: str  # user_name, else friendly_name, else hostname, else vendor, else IP / MAC
    mac: str
    ip: str | None
    vendor: str | None
    hostname: str | None
    type: str | None
    type_confidence: float | None
    status: str
    trusted: bool
    muted: bool
    first_seen: str
    last_seen: str
    highest_severity: Severity | None  # of its open findings
    open_findings: int


class PortOut(Out):
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None


class FindingOut(Out):
    id: int
    device_id: int
    rule_id: str
    port: int | None
    severity: Severity
    title: str
    explanation: str
    fix: str
    first_seen: str
    last_seen: str
    closed_at: str | None


class ChangeOut(Out):
    id: int
    scan_id: int
    device_id: int
    kind: str
    detail: dict | None
    at: str  # when the scan that found it started
    alerted_at: str | None


class DeviceDetailOut(DeviceOut):
    mac_randomised: bool
    os_guess: str | None
    friendly_name: str | None
    user_name: str | None
    type_reasons: list[str]
    ports: list[PortOut]  # from the latest scan that recorded ports for this device
    findings: list[FindingOut]  # open ones first, worst first
    changes: list[ChangeOut]  # newest 20


class ScanOut(Out):
    id: int
    profile: Profile
    trigger: str
    subnet: str
    nmap_version: str | None
    started_at: str
    finished_at: str | None
    status: str
    error: str | None


class ScanRequestIn(BaseModel):
    # extra="forbid": a request that names a target (or anything else) is rejected (guardrail).
    model_config = ConfigDict(extra="forbid")
    profile: Profile = "full"


class ScanRequestOut(Out):
    id: int
    profile: Profile
    requested_at: str
    picked_up_at: str | None
    scan_id: int | None


class ConsentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    i_own_this_network: Literal[True]  # must be sent explicitly, so nothing consents by accident


class ConsentOut(Out):
    ownership_confirmed: bool
    confirmed_at: str | None


class ScoreOut(Out):
    scan_id: int
    at: str
    device_id: int | None  # None = whole network
    score: int


# ---- Helpers ---------------------------------------------------------------------------


def get_session(request: Request) -> Iterator[Session]:
    with request.app.state.sessionmaker() as session:
        yield session


DB = Annotated[Session, Depends(get_session)]


def _setting(session: Session, key: str) -> str | None:
    row = session.get(Setting, key)
    return row.value if row else None


def _display_name(d: Device) -> str:
    return d.user_name or d.friendly_name or d.hostname or d.vendor or d.ip or d.mac


def _open_severities(session: Session, device_ids: list[int]) -> dict[int, list[str]]:
    rows = session.execute(
        select(Finding.device_id, Finding.severity).where(
            Finding.device_id.in_(device_ids), Finding.closed_at.is_(None)
        )
    )
    out: dict[int, list[str]] = {}
    for device_id, severity in rows:
        out.setdefault(device_id, []).append(severity)
    return out


def _device_fields(d: Device, severities: list[str]) -> dict:
    return {
        **{k: getattr(d, k) for k in DeviceOut.model_fields if hasattr(d, k)},
        "name": _display_name(d),
        "highest_severity": min(severities, key=SEVERITIES.index) if severities else None,
        "open_findings": len(severities),
    }


def _changes(session: Session, *where, limit: int) -> list[ChangeOut]:
    rows = session.execute(
        select(Change, Scan.started_at)
        .join(Scan, Change.scan_id == Scan.id)
        .where(*where)
        .order_by(Scan.started_at.desc(), Change.id.desc())
        .limit(limit)
    )
    return [
        ChangeOut(
            id=c.id,
            scan_id=c.scan_id,
            device_id=c.device_id,
            kind=c.kind,
            detail=json.loads(c.detail) if c.detail else None,
            at=at,
            alerted_at=c.alerted_at,
        )
        for c, at in rows
    ]


def _to_c2_time(value: str) -> str:
    """Parse an ISO 8601 time from a query string into the C2 format, or reject it."""
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as e:
        raise HTTPException(422, "since must be an ISO 8601 time, e.g. 2026-11-06T08:00:00Z") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- App -------------------------------------------------------------------------------


def create_app(db_path: str | Path = DEFAULT_DB_PATH) -> FastAPI:
    app = FastAPI(title="Watchtower API", version="0.1.0", description="Contract C4.")
    app.state.sessionmaker = make_sessionmaker(make_engine(db_path))

    @app.get("/api/health", response_model=HealthOut)
    def health(session: DB) -> HealthOut:
        try:
            last = session.scalar(select(func.max(Scan.finished_at)).where(Scan.status == "done"))
            confirmed = _setting(session, "ownership_confirmed") == "1"
        except SQLAlchemyError:
            return HealthOut(database_ok=False, last_scan_at=None, ownership_confirmed=False)
        return HealthOut(database_ok=True, last_scan_at=last, ownership_confirmed=confirmed)

    @app.get("/api/devices", response_model=list[DeviceOut])
    def list_devices(session: DB) -> list[DeviceOut]:
        devices = list(session.scalars(select(Device).order_by(Device.id)))
        sev = _open_severities(session, [d.id for d in devices])
        out = [DeviceOut(**_device_fields(d, sev.get(d.id, []))) for d in devices]
        # Worst first, so the riskiest device is at the top.
        rank = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted(out, key=lambda d: (rank.get(d.highest_severity, len(SEVERITIES)), d.id))

    @app.get("/api/devices/{device_id}", response_model=DeviceDetailOut)
    def get_device(device_id: int, session: DB) -> DeviceDetailOut:
        d = session.get(Device, device_id)
        if d is None:
            raise HTTPException(404, "Device not found")
        latest = session.scalar(select(func.max(Port.scan_id)).where(Port.device_id == d.id))
        ports = session.scalars(
            select(Port).where(Port.device_id == d.id, Port.scan_id == latest).order_by(Port.port)
        )
        findings = session.scalars(
            select(Finding)
            .where(Finding.device_id == d.id)
            .order_by(Finding.closed_at.is_not(None), WORST_FIRST, Finding.id)
        )
        sev = _open_severities(session, [d.id]).get(d.id, [])
        return DeviceDetailOut(
            **_device_fields(d, sev),
            mac_randomised=d.mac_randomised,
            os_guess=d.os_guess,
            friendly_name=d.friendly_name,
            user_name=d.user_name,
            type_reasons=json.loads(d.type_reasons) if d.type_reasons else [],
            ports=[PortOut.model_validate(p) for p in ports],
            findings=[FindingOut.model_validate(f) for f in findings],
            changes=_changes(session, Change.device_id == d.id, limit=20),
        )

    @app.get("/api/findings", response_model=list[FindingOut])
    def list_findings(
        session: DB,
        severity: Severity | None = None,
        open: Annotated[bool | None, Query(description="true = open only, false = closed")] = None,
    ) -> list[FindingOut]:
        q = select(Finding).order_by(WORST_FIRST, Finding.first_seen.desc(), Finding.id)
        if severity:
            q = q.where(Finding.severity == severity)
        if open is not None:
            q = q.where(Finding.closed_at.is_(None) if open else Finding.closed_at.is_not(None))
        return [FindingOut.model_validate(f) for f in session.scalars(q)]

    @app.get("/api/changes", response_model=list[ChangeOut])
    def list_changes(
        session: DB,
        since: Annotated[
            str | None, Query(description="ISO 8601 time, e.g. 2026-11-06T08:00Z")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    ) -> list[ChangeOut]:
        where = [Scan.started_at > _to_c2_time(since)] if since else []
        return _changes(session, *where, limit=limit)

    @app.get("/api/scans", response_model=list[ScanOut])
    def list_scans(session: DB, limit: Annotated[int, Query(ge=1, le=1000)] = 50) -> list[ScanOut]:
        q = select(Scan).order_by(Scan.id.desc()).limit(limit)
        return [ScanOut.model_validate(s) for s in session.scalars(q)]

    @app.get("/api/scans/{scan_id}", response_model=ScanOut)
    def get_scan(scan_id: int, session: DB) -> ScanOut:
        scan = session.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "Scan not found")
        return ScanOut.model_validate(scan)

    @app.post("/api/scans", response_model=ScanRequestOut, status_code=202)
    def request_scan(session: DB, body: ScanRequestIn | None = None) -> ScanRequestOut:
        """Queue a Scan now request. The scanner always uses the configured subnet."""
        req = ScanRequest(profile=(body or ScanRequestIn()).profile, requested_at=utcnow())
        session.add(req)
        session.commit()
        return ScanRequestOut.model_validate(req)

    @app.post("/api/consent", response_model=ConsentOut)
    def consent(body: ConsentIn, session: DB) -> ConsentOut:
        """Record that the user owns this network (WT-FR-24). No scan runs before this."""
        now = utcnow()
        session.merge(Setting(key="ownership_confirmed", value="1"))
        session.merge(Setting(key="ownership_confirmed_at", value=now))
        session.commit()
        return ConsentOut(ownership_confirmed=True, confirmed_at=now)

    @app.get("/api/scores", response_model=list[ScoreOut])
    def list_scores(session: DB) -> list[ScoreOut]:
        rows = session.execute(
            select(Score, Scan.started_at)
            .join(Scan, Score.scan_id == Scan.id)
            .order_by(Score.scan_id, Score.device_id.is_not(None), Score.device_id)
        )
        return [
            ScoreOut(scan_id=s.scan_id, at=at, device_id=s.device_id, score=s.score)
            for s, at in rows
        ]

    return app
