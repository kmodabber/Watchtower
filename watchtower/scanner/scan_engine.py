"""Scan engine interface (WT-FR-13) and gentle Nmap profiles (WT-FR-12).

Callers run a profile against a target and get a contract C1 scan result back.
:class:`FakeEngine` replays a saved Nmap XML fixture so the rest of the app can
be built and tested without scanning. :class:`NmapEngine` runs Nmap and parses
it the same way; the lab test (WT-54) covers that path later.

Nmap argv is built only by :func:`watchtower.scanner.command_builder.build_command`.
Quick scans stop after 120 seconds and full scans after 30 minutes. A timeout
or a non-zero Nmap exit raises :class:`ScanFailed` instead of a C1 result.

Both engines use the WT-62 parser (``parse_nmap_xml``) and wrap the parser
dict in :class:`ScanResult`. A :class:`~watchtower.scanner.nmap_parser.ScanParseError`
from broken XML, or a :class:`~watchtower.scanner.models.ModelError` from
parser output that does not fit the C1 shape, is left to propagate. The
command uses ``-oX -`` so XML arrives on stdout; the engine writes that
stdout to a temp file because the parser reads a path.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Protocol, runtime_checkable

from watchtower.scanner.command_builder import (
    PROFILES,
    build_command,
    require_argv_token,
    validate_command,
)
from watchtower.scanner.mac_helpers import label_host_mac
from watchtower.scanner.models import ScanResult
from watchtower.scanner.nmap_parser import parse_nmap_xml

logger = logging.getLogger(__name__)

# Process limits (WT-FR-12). These are not Nmap flags; build_command owns those.
# full is 30 minutes.
_PROFILE_TIMEOUT_SECONDS: dict[str, int] = {
    "quick": 120,
    "full": 1800,
}


class ScanFailed(Exception):
    """Nmap timed out or exited non-zero, so there is no C1 result.

    Callers catch this and record the scan as failed. There is no scan-status
    column to write yet. A timeout means ``subprocess.run`` already killed Nmap.
    """


def _require_profile(profile: str) -> None:
    if profile not in PROFILES:
        raise ValueError(f"profile must be 'quick' or 'full', got {profile!r}")


def _require_target(target: str) -> None:
    require_argv_token("target", target)


def _enrich_mac_info(result: ScanResult) -> ScanResult:
    """Apply MAC normalization and vendor labeling to discovered hosts."""
    return replace(
        result,
        hosts=[label_host_mac(host) for host in result.hosts],
    )


@runtime_checkable
class ScanEngine(Protocol):
    """Run one profile on one target and return a C1 scan result."""

    def run(self, profile: str, target: str) -> ScanResult:
        """Run ``profile`` (``quick`` or ``full``) against ``target``."""


class FakeEngine:
    """Return a saved Nmap XML fixture through the :class:`ScanEngine` interface.

    ``fixture_dir`` holds WT-55 outputs named ``lab-<profile>.xml``
    (``lab-quick.xml``, ``lab-full.xml``). ``target`` is part of the shared
    signature; the file is chosen by profile, and the saved result is returned
    unchanged apart from a new ``scan_id`` from the parser.
    """

    def __init__(self, fixture_dir: str | Path) -> None:
        self.fixture_dir = Path(fixture_dir)
        if not self.fixture_dir.is_dir():
            raise NotADirectoryError(f"Fixture folder not found: {self.fixture_dir}")

    def run(self, profile: str, target: str) -> ScanResult:
        _require_profile(profile)
        _require_target(target)
        xml_path = self.fixture_dir / f"lab-{profile}.xml"
        if not xml_path.is_file():
            raise FileNotFoundError(
                f"No saved {profile} scan at {xml_path}. "
                "Expected a WT-55 fixture named lab-<profile>.xml."
            )
        result = ScanResult.from_dict(parse_nmap_xml(xml_path, profile=profile))
        return _enrich_mac_info(result)


class NmapEngine:
    """Run Nmap as a subprocess and parse the XML with the WT-96 parser.

    ``exclude_ip`` is the scanner's own address. :func:`build_command` always
    adds it as ``--exclude``. ``run`` still takes ``(profile, target)``;
    ``target`` is the network to scan.

    ``run`` starts a real scan. Unit tests must not call it against a network.
    WT-54 is the lab test for this class.
    """

    def __init__(self, nmap: str = "nmap", *, exclude_ip: str | None = None) -> None:
        self.nmap = nmap
        self.exclude_ip = exclude_ip

    def run(self, profile: str, target: str) -> ScanResult:
        # A missing exclude_ip becomes "", which build_command refuses.
        exclude_ip = self.exclude_ip or ""
        # Flags come only from build_command. argv[0] may be a custom binary.
        command = build_command(profile, target, exclude_ip)
        if self.nmap != command[0]:
            command = [self.nmap, *command[1:]]
        # WT-76: refuse anything that is not the exact approved command.
        validate_command(command, profile, target, exclude_ip)
        timeout_seconds = _PROFILE_TIMEOUT_SECONDS[profile]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout_seconds,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            # subprocess.run kills the Nmap child before raising TimeoutExpired.
            logger.error(
                "%s scan timed out after %s seconds; nmap was stopped",
                profile,
                timeout_seconds,
            )
            raise ScanFailed(f"{profile} scan timed out after {timeout_seconds} seconds") from exc

        if completed.returncode != 0:
            stderr = completed.stderr or ""
            logger.error(
                "nmap exited with status %s on %s scan: %s",
                completed.returncode,
                profile,
                stderr,
            )
            raise ScanFailed(f"{profile} scan failed with exit code {completed.returncode}")

        with tempfile.TemporaryDirectory(prefix="watchtower-nmap-") as tmp:
            xml_path = Path(tmp) / "scan.xml"
            xml_path.write_text(completed.stdout or "", encoding="utf-8")
            result = ScanResult.from_dict(parse_nmap_xml(xml_path, profile=profile))
            return _enrich_mac_info(result)
