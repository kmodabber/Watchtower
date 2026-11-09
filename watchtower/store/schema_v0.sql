-- Watchtower contract C2: database schema v0 (WT-92, first version of WT-FR-20).
-- Plain SQLite so everyone can build against it now. In Stage 2 Adam turns this
-- into SQLAlchemy 2 models plus the first Alembic migration; the tables and
-- column names here are the contract, the SQL itself is a stand-in.
--
-- Conventions
--   * Times are TEXT in ISO 8601 UTC, e.g. '2026-11-07T21:05:00Z'.
--   * Booleans are INTEGER 0/1.
--   * JSON columns are TEXT holding JSON.
--   * MAC addresses are stored lower case with colons, e.g. 'c0:56:e3:12:34:56'
--     (Nmap prints upper case; C6 inventory.yaml uses lower case).
--   * The app opens every connection with:
--       PRAGMA journal_mode = WAL;   PRAGMA foreign_keys = ON;

-- One row per scan run (quick or full). Fed from the C1 header fields.
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY,
    profile       TEXT    NOT NULL CHECK (profile IN ('quick', 'full')),
    trigger       TEXT    NOT NULL DEFAULT 'timer' CHECK (trigger IN ('timer', 'request')),
    subnet        TEXT    NOT NULL,                 -- e.g. '192.168.8.0/24'
    nmap_version  TEXT,
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,                             -- NULL while running
    status        TEXT    NOT NULL DEFAULT 'running'
                          CHECK (status IN ('running', 'done', 'failed')),
    error         TEXT                              -- set when status = 'failed'
);

-- One row per real device, kept across scans. Identity is the MAC address (v0).
CREATE TABLE IF NOT EXISTS devices (
    id               INTEGER PRIMARY KEY,
    mac              TEXT    NOT NULL UNIQUE,
    mac_randomised   INTEGER NOT NULL DEFAULT 0,     -- C1 mac_randomised
    vendor           TEXT,                           -- C1 vendor (from the MAC)
    ip               TEXT,                           -- last IP seen (C1 ip)
    hostname         TEXT,                           -- C1 hostname, mDNS or SSDP name
    os_guess         TEXT,                           -- C1 os_guess
    friendly_name    TEXT,                           -- our best display name
    user_name        TEXT,                           -- name the user typed (PATCH /api/devices)
    type             TEXT,                           -- router, camera, nas, printer, ... (C6 types)
    type_confidence  REAL,                           -- 0.0 to 1.0
    type_reasons     TEXT,                           -- JSON list of plain-English reasons
    trusted          INTEGER NOT NULL DEFAULT 0,
    muted            INTEGER NOT NULL DEFAULT 0,
    first_seen       TEXT    NOT NULL,
    last_seen        TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'online' CHECK (status IN ('online', 'gone'))
);

-- Which devices answered in which scan, and at what IP. Quick scans only fill
-- this table (C1 quick scans have empty ports). Change detection uses it to
-- spot new and gone devices.
CREATE TABLE IF NOT EXISTS sightings (
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip         TEXT    NOT NULL,
    PRIMARY KEY (scan_id, device_id)
);

-- Ports seen on a device in a full scan (one row per port per scan).
-- Fed straight from C1 hosts[].ports[].
CREATE TABLE IF NOT EXISTS ports (
    id         INTEGER PRIMARY KEY,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port       INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol   TEXT    NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp', 'udp')),
    state      TEXT    NOT NULL DEFAULT 'open',      -- C1 state; v0 stores open ports only
    service    TEXT,                                 -- e.g. 'telnet'
    product    TEXT,                                 -- e.g. 'BusyBox telnetd'
    version    TEXT,
    UNIQUE (scan_id, device_id, port, protocol)
);

-- Red flags from the C3 rules. A finding stays open until a later full scan no
-- longer triggers it, then closed_at is set. Title, explanation and fix are
-- copied from the rule so old findings still read correctly if a rule changes.
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY,
    device_id    INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id      TEXT    NOT NULL,                   -- C3 id, e.g. 'RF-TELNET'
    port         INTEGER,                            -- the port that triggered it, if any
    severity     TEXT    NOT NULL CHECK (severity IN ('high', 'medium', 'low', 'info')),
    title        TEXT    NOT NULL,
    explanation  TEXT    NOT NULL,
    fix          TEXT    NOT NULL,
    first_seen   TEXT    NOT NULL,
    last_seen    TEXT    NOT NULL,
    closed_at    TEXT                                -- NULL = still open
);
-- At most one open finding per device, rule and port.
CREATE UNIQUE INDEX IF NOT EXISTS findings_one_open
    ON findings (device_id, rule_id, IFNULL(port, -1)) WHERE closed_at IS NULL;

-- What changed since the previous scan. alerted_at is set once the C5 Discord
-- message that covers it has been sent (one message per scan).
CREATE TABLE IF NOT EXISTS changes (
    id          INTEGER PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL CHECK (kind IN
                    ('new_device', 'device_gone', 'new_port', 'port_closed', 'new_finding')),
    detail      TEXT,                                -- JSON, e.g. {"port": 23, "service": "telnet"}
    alerted_at  TEXT                                 -- NULL = not sent yet
);

-- "Scan now" requests written by the web service and picked up by the scheduler.
-- No target can be stored: the scanner always uses the configured subnet.
CREATE TABLE IF NOT EXISTS scan_requests (
    id            INTEGER PRIMARY KEY,
    profile       TEXT    NOT NULL DEFAULT 'full' CHECK (profile IN ('quick', 'full')),
    requested_at  TEXT    NOT NULL,
    picked_up_at  TEXT,                              -- NULL = still waiting
    scan_id       INTEGER REFERENCES scans(id) ON DELETE SET NULL
);

-- Key/value settings. Known keys in v0:
--   ownership_confirmed ('1'), ownership_confirmed_at (time), subnet,
--   quick_interval_min ('5'), full_interval_min ('15').
-- The Discord webhook is NEVER stored here; it lives in DISCORD_WEBHOOK_URL.
CREATE TABLE IF NOT EXISTS settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- Risk score per scan, per device, plus one row with device_id NULL for the
-- whole network.
CREATE TABLE IF NOT EXISTS scores (
    id         INTEGER PRIMARY KEY,
    scan_id    INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id  INTEGER REFERENCES devices(id) ON DELETE CASCADE,   -- NULL = whole network
    score      INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100)
);
CREATE UNIQUE INDEX IF NOT EXISTS scores_one_per_scan
    ON scores (scan_id, IFNULL(device_id, -1));

CREATE INDEX IF NOT EXISTS ports_by_device    ON ports (device_id, scan_id);
CREATE INDEX IF NOT EXISTS changes_by_scan    ON changes (scan_id);
CREATE INDEX IF NOT EXISTS findings_by_device ON findings (device_id);
