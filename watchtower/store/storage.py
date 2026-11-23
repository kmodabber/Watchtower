"""Save a scan and remember each device across scans (WT-58, WT-FR-07, PRD T-18).

Device identity follows decision D7: match by MAC; a randomised MAC with no MAC match is
matched by hostname. Quick scans have no port data, so they only record sightings.

Not here yet: opening and closing findings (T-18 step 4, WT-66) and calling this from
`watchtower scan` (T-18 step 5, WT-102).
"""

import json
import logging
from collections.abc import Mapping
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from watchtower.scanner.mac_helpers import label_host_mac
from watchtower.scanner.models import Host, ScanResult, TypeGuess
from watchtower.store.models import Device, Port, Scan, Sighting

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


def save_scan(
    session: Session,
    result: ScanResult,
    guesses: Mapping[str, TypeGuess] | None = None,
    trigger: str = "timer",
) -> Scan:
    """Store one C1 scan result. `guesses` maps host IP to its identification.

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
    session.flush()
    return scan
