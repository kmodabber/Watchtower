"""Scan engine interface (WT-FR-13).

Callers run a profile against a target and get a contract C1 scan result back.
:class:`FakeEngine` replays a saved Nmap XML fixture so the rest of the app can
be built and tested without scanning. :class:`NmapEngine` runs Nmap and parses
it the same way; the lab test (WT-54) covers that path later.

Until WT-62 lands, both engines use Joseph's parser v0 (WT-96,
``parse_nmap_xml``).

TODO(WT-103): C1 dataclasses are not in this repo (``main`` has no other
branches, and nothing under ``watchtower/`` defines them). A scan result is the
dict that parser already returns. Do not add a second field layout here.
Replace this alias when the dataclasses land.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from watchtower.scanner.nmap_parser import parse_nmap_xml

# TODO(WT-103): stand-in for the missing C1 dataclasses. Same object the
# WT-96 parser returns; not a new contract.
C1ScanResult = dict[str, Any]

PROFILES = ("quick", "full")

# Command lines copied from the WT-55 fixtures (tests/fixtures/lab-*.xml),
# without the lab-only ``--exclude <scanner ip>``. The caller passes the target.
_NMAP_FLAGS: dict[str, tuple[str, ...]] = {
    "quick": ("-sn", "--privileged"),
    "full": (
        "-sS",
        "-sV",
        "--version-light",
        "--top-ports",
        "1000",
        "-T3",
        "--max-rate",
        "100",
        "--host-timeout",
        "5m",
        "--privileged",
    ),
}


def _require_profile(profile: str) -> None:
    if profile not in PROFILES:
        raise ValueError(f"profile must be 'quick' or 'full', got {profile!r}")


def _require_target(target: str) -> None:
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target is required")
    # One argv element. A leading dash would be read as an nmap option.
    if target.startswith("-") or any(char.isspace() for char in target):
        raise ValueError("target must be a host or subnet, not nmap options")


@runtime_checkable
class ScanEngine(Protocol):
    """Run one profile on one target and return a C1 scan result."""

    def run(self, profile: str, target: str) -> C1ScanResult:
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

    def run(self, profile: str, target: str) -> C1ScanResult:
        _require_profile(profile)
        _require_target(target)
        xml_path = self.fixture_dir / f"lab-{profile}.xml"
        if not xml_path.is_file():
            raise FileNotFoundError(
                f"No saved {profile} scan at {xml_path}. "
                "Expected a WT-55 fixture named lab-<profile>.xml."
            )
        return parse_nmap_xml(xml_path, profile=profile)


class NmapEngine:
    """Run Nmap as a subprocess and parse the XML with the WT-96 parser.

    ``run`` starts a real scan. Unit tests must not call it against a network.
    WT-54 is the lab test for this class.
    """

    def __init__(self, nmap: str = "nmap", timeout: float = 900) -> None:
        self.nmap = nmap
        self.timeout = timeout

    def run(self, profile: str, target: str) -> C1ScanResult:
        _require_profile(profile)
        _require_target(target)
        with tempfile.TemporaryDirectory(prefix="watchtower-nmap-") as tmp:
            xml_path = Path(tmp) / "scan.xml"
            argv = [self.nmap, *_NMAP_FLAGS[profile], "-oX", str(xml_path), target]
            subprocess.run(
                argv,
                check=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return parse_nmap_xml(xml_path, profile=profile)
