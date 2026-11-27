"""The alerts step: tell Discord what changed (WT-68, WT-FR-17, PRD T-22, C5, TC-13).

Run after detect_changes has committed.

  * A high finding opened by this scan gets one `new_finding` change, so it has an alerted_at
    and is retried like any other change. The baseline scan (decision D5) writes none, so
    installing Watchtower does not alert on everything already on the network.
  * Every change not yet alerted, from this or earlier scans, goes into ONE message, worst
    first. Muted devices are left out.
  * alerted_at is set only after delivery, so a failed send is retried after the next scan.
    Changes cut from a long message count as delivered: "…and N more" summarised them.
  * With no webhook the message is logged and counts as delivered, so the log does not repeat
    the same backlog every scan.

The session is committed before the network call, so a slow Discord never holds a database
write lock. That is why this step needs a plain session, not a `.begin()` block.
"""

import json
import logging
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from watchtower.alerts.discord import fit_message, send
from watchtower.scanner.mac_helpers import PRIVATE_ADDRESS_VENDOR
from watchtower.store.changes import _is_baseline
from watchtower.store.models import Change, Device, Finding, Scan, Sighting, utcnow

log = logging.getLogger(__name__)

# Worst first. The label column is padded so the lines read as a list.
_LABELS = {
    "new_finding": "HIGH RISK",
    "new_device": "NEW DEVICE",
    "new_port": "NEW SERVICE",
    "port_closed": "PORT CLOSED",
    "device_gone": "DEVICE GONE",
}
_ORDER = {kind: rank for rank, kind in enumerate(_LABELS)}
_LABEL_WIDTH = 13


def _record_new_findings(session: Session, scan: Scan) -> None:
    """Write a new_finding change for each high finding this scan opened."""
    if scan.profile != "full" or _is_baseline(session, scan):
        return  # only full scans open findings
    # A replayed scan can share a timestamp with an earlier one, so first_seen alone is not
    # enough: a finding on a device that scan already checked was not opened by this one.
    same_time = (
        select(Sighting.device_id)
        .join(Scan, Scan.id == Sighting.scan_id)
        .where(
            Scan.status == "done",
            Scan.profile == "full",
            Scan.id < scan.id,
            Scan.finished_at == scan.finished_at,
        )
    )
    findings = session.scalars(
        select(Finding)
        .join(Device, Device.id == Finding.device_id)
        .where(
            Finding.closed_at.is_(None),
            Finding.severity == "high",
            Finding.first_seen == scan.finished_at,
            Finding.device_id.not_in(same_time),
            Device.muted.is_(False),
        )
        .order_by(Finding.id)
    ).all()
    existing = session.scalars(
        select(Change).where(Change.scan_id == scan.id, Change.kind == "new_finding")
    )
    recorded = {(c.device_id, _detail(c).get("rule_id"), _detail(c).get("port")) for c in existing}
    for f in findings:
        if (f.device_id, f.rule_id, f.port) in recorded:
            continue
        detail = {
            "rule_id": f.rule_id,
            "port": f.port,
            "title": f.title,
            "severity": f.severity,
            "fix": f.fix,
        }
        session.add(
            Change(
                scan_id=scan.id,
                device_id=f.device_id,
                kind="new_finding",
                detail=json.dumps(detail),
            )
        )
    session.flush()


def _pending(session: Session) -> list[tuple[Change, Device]]:
    rows = session.execute(
        select(Change, Device)
        .join(Device, Device.id == Change.device_id)
        .where(Change.alerted_at.is_(None), Device.muted.is_(False))
    ).all()
    pairs = [(change, device) for change, device in rows]
    return sorted(pairs, key=lambda pair: (_ORDER[pair[0].kind], pair[0].id))


def _detail(change: Change) -> dict:
    """The change's JSON detail. Seeded rows may have none, and that must not block alerts."""
    try:
        detail = json.loads(change.detail or "{}")
    except ValueError:
        return {}
    return detail if isinstance(detail, dict) else {}


def _clean(text: str) -> str:
    """Make text from the network safe for one Discord line.

    A device picks its own hostname, so it must not be able to add lines, ping @everyone or
    post a disguised link.
    """
    return " ".join(text.split()).replace("@", "@​").replace("[", "\\[")


def _device_label(d: Device) -> str:
    private = d.vendor == PRIVATE_ADDRESS_VENDOR
    vendor = None if private else d.vendor
    name = d.user_name or d.friendly_name or d.hostname or vendor or "Unknown device"
    extra = "private address" if private else vendor
    return f"{name} ({extra})" if extra and extra != name else name


def _port_label(detail: dict) -> str:
    udp = "/udp" if detail.get("protocol") == "udp" else ""
    service = f" {detail['service']}" if detail.get("service") else ""
    return f"port {detail.get('port')}{udp}{service}"


def _describe(change: Change, device: Device) -> str:
    detail = _detail(change)
    name = _device_label(device)
    ip = detail.get("ip") or device.ip or "unknown address"
    if change.kind == "new_device":
        return f"{name}, {ip}"
    if change.kind == "device_gone":
        return f"{name}, last seen at {ip}"
    if change.kind == "new_finding":
        where = f", port {detail['port']}" if detail.get("port") is not None else ""
        title = str(detail.get("title") or detail.get("rule_id") or "Serious risk").rstrip(".")
        fix = f" What to do: {detail['fix']}" if detail.get("fix") else ""
        return f"{name}{where}: {title}.{fix}"
    return f"{name}, {_port_label(detail)}"


def build_message(subnet: str, pending: list[tuple[Change, Device]], dashboard_url: str) -> str:
    """The one C5 plain-text message, cut to fit Discord with the Details link kept."""
    count = len(pending)
    lines = [f"Watchtower: {count} change{'' if count == 1 else 's'} on {subnet}"]
    for change, device in pending:
        label = _LABELS[change.kind]
        lines.append(f"{label:<{_LABEL_WIDTH}}{_clean(_describe(change, device))}")
    footer = 0
    if dashboard_url:
        lines.append(f"Details: {dashboard_url.rstrip('/')}/changes")
        footer = 1
    return fit_message("\n".join(lines), keep_last=footer)


def send_alerts(
    session: Session,
    scan_id: int,
    webhook_url: str,
    dashboard_url: str,
    sender: Callable[[str, str], bool] | None = None,
) -> bool:
    """Alert on everything not yet delivered. False means it will be retried next scan."""
    scan = session.get(Scan, scan_id)
    if scan is None or scan.status != "done":
        return True
    _record_new_findings(session, scan)
    pending = _pending(session)
    text = build_message(scan.subnet, pending, dashboard_url) if pending else ""
    session.commit()  # keep the new rows even if the send fails; hold no lock while sending
    if not pending:
        return True

    if webhook_url.strip():
        if not (sender or send)(webhook_url, text):
            log.warning("%d changes not alerted; will retry after the next scan", len(pending))
            return False
    else:
        log.info("No Discord webhook configured. Alert not sent:\n%s", text)

    now = utcnow()
    for change, _device in pending:
        change.alerted_at = now
    session.commit()
    return True
