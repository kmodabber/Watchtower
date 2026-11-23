"""One full pass of the scanner pipeline (WT-102, PRD T-17, milestone M2).

scan (engine) > identify devices > red-flag rules > store (C2) > report.

The engine is passed in, so the same code runs Nmap on the lab (NmapEngine) or a saved
scan (FakeEngine). The target always comes from the guardrail (WT-74) in the CLI, never
from a user.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from watchtower.analysis.rules import evaluate, load_rules
from watchtower.scanner.identification import CONFIDENCE_VALUES, confidence_label, identify_scan
from watchtower.scanner.models import Finding, ScanResult, TypeGuess
from watchtower.scanner.scan_engine import FakeEngine, ScanEngine, ScanFailed
from watchtower.store.db import make_engine, make_sessionmaker, upgrade
from watchtower.store.models import SEVERITIES, Scan
from watchtower.store.storage import ownership_confirmed, save_scan

log = logging.getLogger(__name__)

# Rules limited to some device types (D3) only use a guess we are fairly sure of.
# When unsure, raise nothing: a missing finding beats a wrong one.
MIN_TYPE_CONFIDENCE = CONFIDENCE_VALUES["medium"]


class ScanError(Exception):
    """The scan did not finish; it is recorded as a failed scan."""


class NoConsent(ScanError):
    """Nobody has confirmed they own this network yet (WT-FR-24). Nothing is scanned or stored."""


@dataclass
class DeviceReport:
    ip: str
    mac: str | None
    vendor: str | None
    hostname: str | None
    guess: TypeGuess
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst(self) -> int:
        """Index into SEVERITIES of the worst finding (lower is worse); len() if clean."""
        return min((SEVERITIES.index(f.severity) for f in self.findings), default=len(SEVERITIES))


@dataclass
class ScanReport:
    scan_id: int
    profile: str
    subnet: str
    devices: list[DeviceReport]

    @property
    def finding_count(self) -> int:
        return sum(len(d.findings) for d in self.devices)


def rules_device_type(guess: TypeGuess) -> str | None:
    """The device type the rules may rely on, or None when the guess is too weak."""
    if guess.type == "unknown" or guess.confidence < MIN_TYPE_CONFIDENCE:
        return None
    return guess.type


def analyse(
    result: ScanResult, rules: list[dict[str, Any]]
) -> tuple[dict[str, TypeGuess], dict[str, list[Finding]]]:
    """Identify every host and, on a full scan, run the rules. Both maps are keyed by IP."""
    guesses = dict(zip((h.ip for h in result.hosts), identify_scan(result), strict=True))
    findings: dict[str, list[Finding]] = {}
    if result.profile == "full":
        for host in result.hosts:
            findings[host.ip] = evaluate(host, rules_device_type(guesses[host.ip]), rules)
    return guesses, findings


def _record_failure(
    db_path: str | Path, profile: str, subnet: str, trigger: str, error: str
) -> None:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    engine = make_engine(db_path)
    try:
        with make_sessionmaker(engine).begin() as session:
            session.add(
                Scan(
                    profile=profile,
                    trigger=trigger,
                    subnet=subnet,
                    started_at=now,
                    finished_at=now,
                    status="failed",
                    error=error,
                )
            )
    finally:
        engine.dispose()


def _consented(db_path: str | Path) -> bool:
    engine = make_engine(db_path)
    try:
        with make_sessionmaker(engine)() as session:
            return ownership_confirmed(session)
    finally:
        engine.dispose()


def run_scan(
    engine: ScanEngine,
    profile: str,
    target: str,
    db_path: str | Path,
    *,
    trigger: str = "request",
    rules: list[dict[str, Any]] | None = None,
) -> ScanReport:
    """Scan ``target`` once, store the result and return a report.

    A scan that fails (timeout, Nmap error, refused command, broken XML) is stored with
    status ``failed`` and raises ScanError. Without ownership consent nothing runs and
    NoConsent is raised; a FakeEngine replay skips that check because it never touches the
    network.
    """
    upgrade(db_path)
    if not isinstance(engine, FakeEngine) and not _consented(db_path):
        log.warning("waiting for ownership confirmation")
        raise NoConsent(
            "waiting for ownership confirmation: run `watchtower consent --i-own-this-network` "
            "or tick the statement on the dashboard"
        )
    try:
        result = engine.run(profile, target)
    except (ScanFailed, ValueError, OSError) as exc:
        # ScanFailed: timeout or Nmap error. ValueError covers ScanParseError,
        # CommandNotAllowed and ModelError. OSError: Nmap or a fixture is missing.
        _record_failure(db_path, profile, target, trigger, str(exc))
        raise ScanError(f"{profile} scan of {target} failed: {exc}") from exc

    guesses, findings = analyse(result, rules if rules is not None else load_rules())
    engine_db = make_engine(db_path)
    try:
        with make_sessionmaker(engine_db).begin() as session:
            scan = save_scan(session, result, guesses, trigger=trigger, findings=findings)
            scan_id = scan.id
    finally:
        engine_db.dispose()

    devices = [
        DeviceReport(h.ip, h.mac, h.vendor, h.hostname, guesses[h.ip], findings.get(h.ip, []))
        for h in result.hosts
    ]
    devices.sort(key=lambda d: (d.worst, _ip_key(d.ip)))
    report = ScanReport(scan_id, result.profile, result.subnet, devices)
    log.info("Scan %s stored: %d devices, %d findings", scan_id, len(devices), report.finding_count)
    return report


def _ip_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999,)


def _device_name(d: DeviceReport) -> str:
    return d.hostname or d.vendor or "no name"


def format_report(report: ScanReport) -> str:
    """Plain-text report for the terminal: worst devices first."""
    lines = [
        f"Watchtower scan {report.scan_id} ({report.profile}) of {report.subnet}: "
        f"{len(report.devices)} devices, {report.finding_count} findings",
        "",
    ]
    for d in report.devices:
        label = (
            f"{d.guess.type} ({confidence_label(d.guess.confidence)} confidence)"
            if d.guess.type != "unknown"
            else "unknown type"
        )
        lines.append(f"{d.ip:<15} {label:<32} {_device_name(d)}  [{d.mac or 'no MAC'}]")
        for f in sorted(d.findings, key=lambda f: SEVERITIES.index(f.severity)):
            where = f" (port {f.port})" if f.port is not None else ""
            lines.append(f"    {f.severity.upper():<7} {f.rule_id}: {f.title}{where}")
            lines.append(f"            Fix: {f.fix}")
    if report.profile == "quick":
        lines += ["", "Quick scans only find devices. Run a full scan for ports and findings."]
    return "\n".join(lines)
