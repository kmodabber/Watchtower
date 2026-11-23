"""Save a scan and remember each device across scans (WT-58, WT-FR-07, PRD T-18).

Device identity follows decision D7: match by MAC; a randomised MAC with no MAC match is
matched by hostname. Quick scans have no port data, so they only record sightings.

Findings (T-18 step 4, WT-66, decision D6): a full scan opens a finding the first time a
device has it, keeps it open while later full scans still see it, and closes it when a full
scan sees the device without it. Quick scans never touch findings. `watchtower scan`
(WT-102) calls this.
"""

import json
import logging
from collections.abc import Mapping
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from watchtower.scanner.mac_helpers import label_host_mac
from watchtower.scanner.models import Finding, Host, ScanResult, TypeGuess
from watchtower.store.models import Device, Port, Scan, Sighting
from watchtower.store.models import Finding as FindingRow

log = logging.getLogger(__name__)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_device(session: Session, host: Host, taken: set[int]) -> Device | None:
    device = session.scalar(select(Device).where(Device.mac == host.mac))
    if device or not (host.mac_randomised and host.hostname):
        return device
    # A phone that rotated its MAC: same hostname, also randomised, not already this scan.
    return session.scalar(
        select(Device)
        .where(
            Device.hostname == host.hostname,
            Device.mac_randomised.is_(True),
            Device.id.not_in(taken),
        )
        .order_by(Device.last_seen.desc())
        .limit(1)
    )


def _update_findings(session: Session, device: Device, found: list[Finding], at: str) -> None:
    """Open, refresh and close one device's findings after a full scan (D6)."""
    open_rows = {
        (row.rule_id, row.port): row
        for row in session.scalars(
            select(FindingRow).where(
                FindingRow.device_id == device.id, FindingRow.closed_at.is_(None)
            )
        )
    }
    seen: set[tuple[str, int | None]] = set()
    for f in found:
        key = (f.rule_id, f.port)
        if key in seen:
            continue
        seen.add(key)
        row = open_rows.get(key)
        if row is None:
            session.add(
                FindingRow(
                    device_id=device.id,
                    rule_id=f.rule_id,
                    port=f.port,
                    severity=f.severity,
                    title=f.title,
                    explanation=f.explanation,
                    fix=f.fix,
                    first_seen=at,
                    last_seen=at,
                )
            )
        else:
            row.last_seen = at
            # Rule text may have been edited since the finding opened; show the current one.
            row.severity, row.title = f.severity, f.title
            row.explanation, row.fix = f.explanation, f.fix
    for key, row in open_rows.items():
        if key not in seen:
            row.closed_at = at  # the risk is gone: this full scan saw the device without it


def save_scan(
    session: Session,
    result: ScanResult,
    guesses: Mapping[str, TypeGuess] | None = None,
    trigger: str = "timer",
    findings: Mapping[str, list[Finding]] | None = None,
) -> Scan:
    """Store one C1 scan result. `guesses` and `findings` map host IP to that host's
    identification and red-flag findings. Findings are only used on full scans (D6).

    Call it inside one transaction, e.g. `with make_sessionmaker(engine).begin() as s:`,
    so a failure part-way leaves nothing behind.
    """
    full = result.profile == "full"
    at = _ts(result.finished_at)
    scan = Scan(
        profile=result.profile,
        trigger=trigger,
        subnet=result.subnet,
        nmap_version=result.nmap_version,
        started_at=_ts(result.started_at),
        finished_at=at,
        status="done",
    )
    session.add(scan)
    session.flush()

    taken: set[int] = set()
    for raw in result.hosts:
        if not raw.mac:
            log.debug("Skipping %s: no MAC address to recognise it by", raw.ip)
            continue
        host = label_host_mac(raw)  # lower-case MAC, private-address label (WT-57)
        device = _find_device(session, host, taken)
        if device is not None and device.id in taken:
            # Same device answered on a second IP (e.g. a router with two addresses).
            # Saving it twice would break the one-row-per-scan rules and lose the scan.
            log.info("%s answered again on %s; keeping its first address", host.mac, host.ip)
            continue
        if device is None:
            device = Device(mac=host.mac, first_seen=at)
            session.add(device)
        device.mac = host.mac
        device.mac_randomised = host.mac_randomised
        device.vendor = host.vendor
        device.ip = host.ip
        device.hostname = host.hostname or device.hostname
        device.last_seen = at
        device.status = "online"
        guess = (guesses or {}).get(host.ip)
        if full and guess:
            device.type = guess.type
            device.type_confidence = guess.confidence
            device.type_reasons = json.dumps(guess.reasons)
        session.flush()
        taken.add(device.id)

        session.add(Sighting(scan_id=scan.id, device_id=device.id, ip=host.ip))
        if full:
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
            if findings is not None:  # None: the caller did not run the rules, so leave them
                _update_findings(session, device, list(findings.get(host.ip, [])), at)
    session.flush()
    return scan
