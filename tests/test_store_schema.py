"""WT-71 (WT-FR-20): the Alembic migrations build contract C2, and it accepts C1-shaped data.

Started as the WT-92 schema v0 checks; they now run against the real migrations.
"""

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command

from watchtower.store.db import alembic_config, make_engine, upgrade

# A hand-written C1 scan result for the lab camera (see 05 section 3, C1).
C1_SCAN = {
    "scan_id": "fixture-1",
    "profile": "full",
    "subnet": "172.28.0.0/24",
    "started_at": "2026-11-07T21:00:00Z",
    "finished_at": "2026-11-07T21:05:00Z",
    "nmap_version": "7.95",
    "hosts": [
        {
            "ip": "172.28.0.3",
            "mac": "C0:56:E3:12:34:56",
            "vendor": "Hangzhou Hikvision Digital Technology",
            "mac_randomised": False,
            "hostname": None,
            "os_guess": None,
            "ports": [
                {
                    "port": 23,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "telnet",
                    "product": "BusyBox telnetd",
                    "version": None,
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": None,
                    "version": None,
                },
            ],
        }
    ],
}


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "watchtower.db"
    upgrade(path)  # migrations on an empty database (PRD P2-04 contract test)
    return path


@pytest.fixture
def db(db_path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    yield conn
    conn.close()


def test_models_and_migrations_agree(db_path: Path) -> None:
    # Fails when a model changed without a new migration.
    command.check(alembic_config(db_path))


def test_upgrade_twice_is_harmless(db_path: Path) -> None:
    upgrade(db_path)


def test_app_connections_use_wal_foreign_keys_and_busy_timeout(db_path: Path) -> None:
    engine = make_engine(db_path)
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert conn.exec_driver_sql("PRAGMA busy_timeout").scalar() == 5000
    engine.dispose()


def store(conn: sqlite3.Connection, scan: dict) -> int:
    """Tiny stand-in for the real store: writes one C1 result into C2."""
    scan_id = conn.execute(
        "INSERT INTO scans (profile, subnet, nmap_version, started_at, finished_at, status)"
        " VALUES (?, ?, ?, ?, ?, 'done')",
        (
            scan["profile"],
            scan["subnet"],
            scan["nmap_version"],
            scan["started_at"],
            scan["finished_at"],
        ),
    ).lastrowid
    for host in scan["hosts"]:
        mac = host["mac"].lower()
        conn.execute(
            "INSERT INTO devices (mac, mac_randomised, vendor, ip, hostname, os_guess,"
            " type_reasons, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, last_seen = excluded.last_seen",
            (
                mac,
                int(host["mac_randomised"]),
                host["vendor"],
                host["ip"],
                host["hostname"],
                host["os_guess"],
                json.dumps([]),
                scan["finished_at"],
                scan["finished_at"],
            ),
        )
        device_id = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,)).fetchone()[0]
        conn.execute("INSERT INTO sightings VALUES (?, ?, ?)", (scan_id, device_id, host["ip"]))
        for p in host["ports"]:
            conn.execute(
                "INSERT INTO ports (scan_id, device_id, port, protocol, state, service,"
                " product, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    device_id,
                    p["port"],
                    p["protocol"],
                    p["state"],
                    p["service"],
                    p["product"],
                    p["version"],
                ),
            )
    return scan_id


def test_all_c2_tables_exist(db: sqlite3.Connection) -> None:
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {
        "devices",
        "scans",
        "sightings",
        "ports",
        "findings",
        "changes",
        "scan_requests",
        "settings",
        "scores",
    } <= names


def test_c1_scan_result_fits_c2(db: sqlite3.Connection) -> None:
    store(db, C1_SCAN)
    mac, vendor = db.execute("SELECT mac, vendor FROM devices").fetchone()
    assert mac == "c0:56:e3:12:34:56"  # same form as lab/inventory.yaml (C6)
    assert vendor.startswith("Hangzhou Hikvision")
    ports = [r[0] for r in db.execute("SELECT port FROM ports ORDER BY port")]
    assert ports == [23, 80]


def test_second_scan_reuses_the_device(db: sqlite3.Connection) -> None:
    store(db, C1_SCAN)
    store(db, C1_SCAN)
    assert db.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1
    assert db.execute("SELECT COUNT(*) FROM sightings").fetchone()[0] == 2


def test_only_one_open_finding_per_device_rule_and_port(db: sqlite3.Connection) -> None:
    store(db, C1_SCAN)
    row = (1, "RF-TELNET", 23, "high", "Telnet is open", "why", "fix", "t", "t")
    sql = (
        "INSERT INTO findings (device_id, rule_id, port, severity, title, explanation,"
        " fix, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    db.execute(sql, row)
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(sql, row)
    db.execute("UPDATE findings SET closed_at = 't2'")
    db.execute(sql, row)  # allowed again once the old one is closed


def test_bad_values_are_rejected(db: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO scans (profile, subnet, started_at) VALUES ('aggressive', 'x', 't')"
        )
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO ports (scan_id, device_id, port) VALUES (999, 999, 23)")
