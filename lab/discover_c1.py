"""WT-95 Stage 1: quick C1 discovery of the isolated Watchtower Docker lab.

Inside the scanner dev container, from /workspace:
    python -m lab.discover_c1

This is a Stage 1 lab demonstration, not the production scan engine.
C1 conversion comes from independent XML parser (WT-96).
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

LAB_SUBNET = ipaddress.ip_network("172.28.0.0/24")
DEV_CONFIG = "/workspace/lab/watchtower.dev.toml"


def scanner_lab_ip() -> str:
    """Only permit the expected dev container and isolated lab subnet."""
    if os.environ.get("WATCHTOWER_CONFIG") != DEV_CONFIG:
        raise RuntimeError("Run this demo inside the configured lab scanner container.")

    result = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", "eth0"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    fields = result.stdout.split()
    if "inet" not in fields:
        raise RuntimeError("No IPv4 address found on eth0.")

    interface = ipaddress.ip_interface(fields[fields.index("inet") + 1])
    if interface.network != LAB_SUBNET:
        raise RuntimeError(
            f"Refusing scan: eth0 is on {interface.network}, not {LAB_SUBNET}."
        )
    return str(interface.ip)


def parse_scan_xml(xml_path: Path) -> dict[str, Any]:
    """Delegate XML-to-C1 conversion to the shared WT-96 parser.

    Delaying the import lets the lab-only command tests run before WT-96 merges.
    """
    try:
        from watchtower.scanner.nmap_parser import parse_nmap_xml
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "C1 parser is not available yet. Merge WT-96 / xml-Parser first, "
            "or use it locally for integration testing."
        ) from exc
    return parse_nmap_xml(xml_path, profile="quick")


def discover_c1() -> dict[str, Any]:
    """Execute one approved quick scan, convert its XML to C1 and return it."""
    scanner_ip = scanner_lab_ip()
    with tempfile.TemporaryDirectory(prefix="watchtower-lab-") as tmp:
        xml_path = Path(tmp) / "quick.xml"
        subprocess.run(
            [
                "nmap", "-sn", "--privileged", "-oX", str(xml_path),
                "--exclude", scanner_ip, str(LAB_SUBNET),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return parse_scan_xml(xml_path)


def main() -> int:
    try:
        data = discover_c1()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        print(f"Lab discovery failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
