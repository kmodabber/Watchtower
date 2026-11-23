"""Work out what changed since the last scan (WT-67, WT-FR-16, PRD T-20, TC-12).

Call detect_changes in the same transaction, right after save_scan. Only scans with status
'done' count; failed scans are ignored everywhere.

  * Baseline (decision D5): the first done scan records nothing.
  * new_device: the device was created by this scan.
  * new_port / port_closed: full scans only, against the device's previous full scan.
  * device_gone: on every scan, for an online device not seen for 3 quick scans in a row.

The `new_finding` kind is not written here: alerts (WT-68) read new high findings directly
(PRD T-22).
"""

import json
import logging
from collections import Counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from watchtower.store.models import Change, Device, Port, Scan, Sighting

log = logging.getLogger(__name__)

GONE_AFTER_QUICK_SCANS = 3


def _change(scan: Scan, device_id: int, kind: str, **detail: object) -> Change:
    return Change(scan_id=scan.id, device_id=device_id, kind=kind, detail=json.dumps(detail))


def _is_baseline(session: Session, scan: Scan) -> bool:
    earlier = session.scalar(
        select(Scan.id).where(Scan.status == "done", Scan.id < scan.id).limit(1)
    )
    return earlier is None


def _new_devices(session: Session, scan: Scan) -> list[Change]:
    # Two scans can share a timestamp (same second, or a replayed saved scan), so first_seen
    # alone is not enough: a device sighted by an earlier scan is never new.
    devices = session.scalars(
        select(Device)
        .join(Sighting, Sighting.device_id == Device.id)
        .where(
            Sighting.scan_id == scan.id,
            Device.first_seen == scan.finished_at,
            Device.id.not_in(select(Sighting.device_id).where(Sighting.scan_id < scan.id)),
        )
        .order_by(Device.id)
    )
    return [
        _change(scan, d.id, "new_device", ip=d.ip, mac=d.mac, hostname=d.hostname, vendor=d.vendor)
        for d in devices
    ]


def _previous_full_scan(session: Session, scan: Scan, device_id: int) -> int | None:
    return session.scalar(
        select(Scan.id)
        .join(Sighting, Sighting.scan_id == Scan.id)
        .where(
            Sighting.device_id == device_id,
            Scan.status == "done",
            Scan.profile == "full",
            Scan.id < scan.id,
        )
        .order_by(Scan.id.desc())
        .limit(1)
    )


def _open_ports(
    session: Session, scan_id: int, device_id: int
) -> dict[tuple[int, str], str | None]:
    """Map (port, protocol) to service for one device's open ports in one scan."""
    rows = session.execute(
        select(Port.port, Port.protocol, Port.service).where(
            Port.scan_id == scan_id, Port.device_id == device_id, Port.state == "open"
        )
    )
    return {(port, protocol): service for port, protocol, service in rows}


def _port_changes(session: Session, scan: Scan) -> list[Change]:
    if scan.profile != "full":
        return []  # quick scans have no port data
    changes: list[Change] = []
    device_ids = session.scalars(
        select(Sighting.device_id).where(Sighting.scan_id == scan.id).order_by(Sighting.device_id)
    ).all()
    for device_id in device_ids:
        previous_id = _previous_full_scan(session, scan, device_id)
        if previous_id is None:
            continue  # the device's first full scan is its port baseline
        now = _open_ports(session, scan.id, device_id)
        before = _open_ports(session, previous_id, device_id)
        for key in sorted(now.keys() - before.keys()):
            port, protocol = key
            changes.append(
                _change(scan, device_id, "new_port", port=port, protocol=protocol, service=now[key])
            )
        for key in sorted(before.keys() - now.keys()):
            port, protocol = key
            changes.append(
                _change(
                    scan,
                    device_id,
                    "port_closed",
                    port=port,
                    protocol=protocol,
                    service=before[key],
                )
            )
    return changes


def _gone_devices(session: Session, scan: Scan) -> list[Change]:
    """Mark devices missing for the last 3 quick scans. Once gone they are not recorded again."""
    quick = session.scalars(
        select(Scan)
        .where(Scan.status == "done", Scan.profile == "quick", Scan.id <= scan.id)
        .order_by(Scan.id.desc())
        .limit(GONE_AFTER_QUICK_SCANS)
    ).all()
    if len(quick) < GONE_AFTER_QUICK_SCANS:
        return []
    oldest_start = quick[-1].started_at
    devices = session.scalars(
        select(Device)
        .where(Device.status == "online", Device.last_seen < oldest_start)
        .order_by(Device.id)
    ).all()
    changes: list[Change] = []
    for device in devices:
        device.status = "gone"
        changes.append(
            _change(scan, device.id, "device_gone", ip=device.ip, last_seen=device.last_seen)
        )
    return changes


def detect_changes(session: Session, scan_id: int) -> list[Change]:
    """Record and return what changed in this stored scan.

    Safe to call twice: a scan that already has changes just returns them.
    """
    scan = session.get(Scan, scan_id)
    if scan is None or scan.status != "done":
        return []
    existing = list(
        session.scalars(select(Change).where(Change.scan_id == scan_id).order_by(Change.id))
    )
    if existing:
        return existing
    if _is_baseline(session, scan):
        log.info("Scan %s is the baseline: no changes recorded", scan_id)
        return []

    changes = [
        *_new_devices(session, scan),
        *_port_changes(session, scan),
        *_gone_devices(session, scan),
    ]
    session.add_all(changes)
    session.flush()
    counts = Counter(c.kind for c in changes)
    log.info(
        "Scan %s changes: %d new devices, %d gone, %d ports opened, %d ports closed",
        scan_id,
        counts["new_device"],
        counts["device_gone"],
        counts["new_port"],
        counts["port_closed"],
    )
    return changes
