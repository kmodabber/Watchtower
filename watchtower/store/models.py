"""Contract C2: the database schema as SQLAlchemy 2 models (WT-FR-20).

These models are the source of truth. Any change here needs a new Alembic migration
(`uv run alembic revision --autogenerate -m "..."`); CI fails if they drift apart.

Conventions (unchanged from schema v0):
  * Times are TEXT in ISO 8601 UTC, e.g. '2026-11-07T21:05:00Z' (see utcnow()).
  * Booleans are INTEGER 0/1. JSON columns are TEXT holding JSON.
  * MAC addresses are lower case with colons. One device per MAC (identity, v0).
"""

from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

PROFILES = ("quick", "full")
SEVERITIES = ("high", "medium", "low", "info")  # worst first
CHANGE_KINDS = ("new_device", "device_gone", "new_port", "port_closed", "new_finding")


def utcnow() -> str:
    """Current time in the C2 text format."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Base(DeclarativeBase):
    pass


class Scan(Base):
    """One row per scan run (quick or full)."""

    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(_in("profile", PROFILES), name="scans_profile"),
        CheckConstraint(_in("trigger", ("timer", "request")), name="scans_trigger"),
        CheckConstraint(_in("status", ("running", "done", "failed")), name="scans_status"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    profile: Mapped[str] = mapped_column(String)
    trigger: Mapped[str] = mapped_column(String, default="timer", server_default="timer")
    subnet: Mapped[str] = mapped_column(String)
    nmap_version: Mapped[str | None] = mapped_column(String)
    started_at: Mapped[str] = mapped_column(String)
    finished_at: Mapped[str | None] = mapped_column(String)  # NULL while running
    status: Mapped[str] = mapped_column(String, default="running", server_default="running")
    error: Mapped[str | None] = mapped_column(String)  # set when status = 'failed'


class Device(Base):
    """One row per real device, kept across scans."""

    __tablename__ = "devices"
    __table_args__ = (CheckConstraint(_in("status", ("online", "gone")), name="devices_status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    mac: Mapped[str] = mapped_column(String, unique=True)
    mac_randomised: Mapped[bool] = mapped_column(default=False, server_default=text("0"))
    vendor: Mapped[str | None] = mapped_column(String)
    ip: Mapped[str | None] = mapped_column(String)  # last IP seen
    hostname: Mapped[str | None] = mapped_column(String)
    os_guess: Mapped[str | None] = mapped_column(String)
    friendly_name: Mapped[str | None] = mapped_column(String)  # mDNS / SSDP name
    user_name: Mapped[str | None] = mapped_column(String)  # typed by the user
    type: Mapped[str | None] = mapped_column(String)
    type_confidence: Mapped[float | None] = mapped_column(Float)  # 0.0 to 1.0
    type_reasons: Mapped[str | None] = mapped_column(String)  # JSON list
    trusted: Mapped[bool] = mapped_column(default=False, server_default=text("0"))
    muted: Mapped[bool] = mapped_column(default=False, server_default=text("0"))
    first_seen: Mapped[str] = mapped_column(String)
    last_seen: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="online", server_default="online")


class Sighting(Base):
    """Which devices answered in which scan, and at what IP (quick and full)."""

    __tablename__ = "sightings"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), primary_key=True
    )
    ip: Mapped[str] = mapped_column(String)


class Port(Base):
    """An open port on a device in a full scan (one row per port per scan)."""

    __tablename__ = "ports"
    __table_args__ = (
        CheckConstraint("port BETWEEN 1 AND 65535", name="ports_port"),
        CheckConstraint(_in("protocol", ("tcp", "udp")), name="ports_protocol"),
        UniqueConstraint("scan_id", "device_id", "port", "protocol"),
        Index("ports_by_device", "device_id", "scan_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String, default="tcp", server_default="tcp")
    state: Mapped[str] = mapped_column(String, default="open", server_default="open")
    service: Mapped[str | None] = mapped_column(String)
    product: Mapped[str | None] = mapped_column(String)
    version: Mapped[str | None] = mapped_column(String)


class Finding(Base):
    """A red flag from the C3 rules. Open until a later full scan no longer triggers it."""

    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(_in("severity", SEVERITIES), name="findings_severity"),
        # At most one open finding per device, rule and port.
        Index(
            "findings_one_open",
            "device_id",
            "rule_id",
            func.ifnull(text("port"), -1),
            unique=True,
            sqlite_where=text("closed_at IS NULL"),
        ),
        Index("findings_by_device", "device_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    rule_id: Mapped[str] = mapped_column(String)  # C3 id, e.g. 'RF-TELNET'
    port: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    explanation: Mapped[str] = mapped_column(String)
    fix: Mapped[str] = mapped_column(String)
    first_seen: Mapped[str] = mapped_column(String)
    last_seen: Mapped[str] = mapped_column(String)
    closed_at: Mapped[str | None] = mapped_column(String)  # NULL = still open


class Change(Base):
    """What changed since the previous scan. alerted_at is set once Discord was told (C5)."""

    __tablename__ = "changes"
    __table_args__ = (
        CheckConstraint(_in("kind", CHANGE_KINDS), name="changes_kind"),
        Index("changes_by_scan", "scan_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String)
    detail: Mapped[str | None] = mapped_column(String)  # JSON
    alerted_at: Mapped[str | None] = mapped_column(String)


class ScanRequest(Base):
    """A Scan now request from the web service. No target column on purpose (guardrail)."""

    __tablename__ = "scan_requests"
    __table_args__ = (CheckConstraint(_in("profile", PROFILES), name="scan_requests_profile"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    profile: Mapped[str] = mapped_column(String, default="full", server_default="full")
    requested_at: Mapped[str] = mapped_column(String)
    picked_up_at: Mapped[str | None] = mapped_column(String)  # NULL = still waiting
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))


class Setting(Base):
    """Key/value settings: ownership_confirmed, ownership_confirmed_at, subnet, intervals.
    The Discord webhook is never stored here."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(String)


class Score(Base):
    """Risk score per scan, per device, plus one row with device_id NULL for the network."""

    __tablename__ = "scores"
    __table_args__ = (
        CheckConstraint("score BETWEEN 0 AND 100", name="scores_score"),
        Index("scores_one_per_scan", "scan_id", func.ifnull(text("device_id"), -1), unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    score: Mapped[int] = mapped_column(Integer)
