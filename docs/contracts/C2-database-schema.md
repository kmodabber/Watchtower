# C2. Database schema v1

Owner: Adam. Status: v1, Nov 13 2026 (WT-71). v0 draft Nov 7 2026 (WT-92), written by Kam.
Source of truth: the SQLAlchemy models in `watchtower/store/models.py`, built by the Alembic
migrations in `watchtower/store/migrations/`. Checked by `tests/test_store_schema.py`.

SQLite with WAL and foreign keys on. Times are ISO 8601 UTC text, booleans are 0/1,
JSON columns are text, MACs are lower case with colons (same as `lab/inventory.yaml`).
Every connection also sets `busy_timeout=5000`. Tables and columns are unchanged from v0.

| Table | Columns | Filled from |
|---|---|---|
| scans | id, profile (quick, full), trigger (timer, request), subnet, nmap_version, started_at, finished_at, status (running, done, failed), error | C1 header |
| devices | id, mac (unique), mac_randomised, vendor, ip, hostname, os_guess, friendly_name, user_name, type, type_confidence, type_reasons (JSON), trusted, muted, first_seen, last_seen, status (online, gone) | C1 hosts + identification |
| sightings | scan_id, device_id, ip | every C1 host, quick and full |
| ports | id, scan_id, device_id, port, protocol, state, service, product, version | C1 hosts[].ports[] (full scans) |
| findings | id, device_id, rule_id, port, severity (high, medium, low, info), title, explanation, fix, first_seen, last_seen, closed_at | C3 rules |
| changes | id, scan_id, device_id, kind (new_device, device_gone, new_port, port_closed, new_finding), detail (JSON), alerted_at | change detection, read by C5 |
| scan_requests | id, profile, requested_at, picked_up_at, scan_id | POST /api/scans (C4) |
| settings | key, value | consent, subnet, intervals (never the webhook) |
| scores | id, scan_id, device_id (empty = whole network), score 0 to 100 | risk score |

Rules that matter:

- One device per MAC address. A second scan updates `ip` and `last_seen`, it never adds a new row.
- At most one open finding per device, rule and port. Closing it (setting `closed_at`) allows a new one later.
- `scan_requests` has no target column on purpose: Scan now always uses the configured subnet (guardrail).
- No secrets and no real scan results go in git. Local databases live in `var/` (ignored).

## What changed from the 05 table (accepted by Adam, WT-71)

1. **New `sightings` table.** Quick scans have no ports, so without it nothing records which devices answered a quick scan, and "device gone" can't be worked out.
2. **New columns:** `devices.ip` and `devices.os_guess` (both in C1), `scans.trigger` and `scans.nmap_version`, `ports.state` (in C1), `findings.port`, `scan_requests.profile`, `scores.id`.
3. **New change kind `new_finding`**, because C5 (Cliff, Nov 5) sends an alert for a new high-severity finding.

## Decisions on the v0 open questions (WT-71)

- **MAC as identity:** yes for v0. A phone that rotates its MAC shows up as a new device;
  a hostname fallback (D7) can come later as a migration without breaking the API.
- **C1 `scan_id`:** not stored. The database's integer `scans.id` is the scan id.
- **History clean-up:** deferred to before the Pi install. It needs no schema change.
