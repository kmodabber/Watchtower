"""
nmap_parser.py – Contract C1 Nmap XML parser
=============================================
Converts a saved Nmap XML file (quick or full) into a ScanResult dict that
matches contract C1.  No other module should read Nmap output directly.

Running as a script
-------------------
When executed directly the parser reads both lab fixture XMLs and writes
their C1-compliant JSON next to them (the parser tests compare against these):

    python -m watchtower.scanner.nmap_parser
    # or
    python watchtower/scanner/nmap_parser.py

Output files (committed as reference examples of the C1 contract):
    tests/fixtures/lab-quick.c1.json
    tests/fixtures/lab-full.c1.json

Contract C1 shape
-----------------
{
    "scan_id":      str,          # UUID v4 generated at parse time
    "profile":      "quick"|"full",
    "subnet":       str,          # CIDR extracted from nmap args, e.g. "172.28.0.0/24"
    "started_at":   str,          # ISO-8601 UTC
    "finished_at":  str,          # ISO-8601 UTC
    "nmap_version": str,
    "hosts": [
        {
            "ip":             str,
            "mac":            str | None,
            "vendor":         str | None,
            "mac_randomised": bool,
            "hostname":       str | None,
            "os_guess":       str | None,
            "ports": [
                {
                    "port":     int,
                    "protocol": str,
                    "state":    str,
                    "service":  str | None,
                    "product":  str | None,
                    "version":  str | None,
                }
            ]
        }
    ]
}

Usage
-----
    from watchtower.scanner.nmap_parser import parse_nmap_xml

    result = parse_nmap_xml(Path("tests/fixtures/lab-quick.xml"), profile="quick")
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def _ts_to_iso(unix_ts: str) -> str:
    """Convert a Unix timestamp string to an ISO-8601 UTC string."""
    return datetime.fromtimestamp(int(unix_ts), tz=UTC).isoformat()


def _detect_profile(args: str) -> str:
    """
    Infer 'quick' or 'full' from the nmap command-line args stored in the XML.

    Quick scans use ``-sn`` (ping-only, no port scan).
    Full scans use ``-sS`` / ``-sV`` etc.
    """
    # Compare whole tokens: a regex \b never matches between a space and "-".
    flags = set(args.split())
    if "-sn" in flags:
        return "quick"
    if flags & {"-sS", "-sT", "-sU", "-sA", "-sV"}:
        return "full"
    return "quick"


def _extract_subnet(args: str) -> str | None:
    """
    Pull the target CIDR from the nmap args string.
    Looks for the last token that looks like an IPv4 CIDR (e.g. 172.28.0.0/24).
    """
    matches = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", args)
    return matches[-1] if matches else None


def _is_mac_randomised(mac: str | None) -> bool:
    """
    A MAC is considered locally-administered (i.e. randomised / spoofed) when
    bit 1 of the first octet is set (the LA bit).

    Examples
    --------
    A2:FC:AE:… → 0xA2 = 1010_0010 → bit-1 set → True
    3A:7F:21:… → 0x3A = 0011_1010 → bit-1 set → True
    50:C7:BF:… → 0x50 = 0101_0000 → bit-1 clear → False
    """
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------


def parse_nmap_xml(xml_path: str | Path, profile: str | None = None) -> dict[str, Any]:
    """
    Parse a Nmap XML output file and return a C1-compliant ScanResult dict.

    Parameters
    ----------
    xml_path:
        Path to the ``.xml`` file produced by ``nmap -oX``.
    profile:
        ``"quick"`` or ``"full"``.  If *None* the profile is auto-detected
        from the nmap command-line args embedded in the XML.

    Returns
    -------
    dict
        A ScanResult that conforms to contract C1.

    Raises
    ------
    ValueError
        When the XML is missing required attributes or is structurally invalid.
    ET.ParseError
        When the file is not valid XML.
    FileNotFoundError
        When *xml_path* does not exist.
    """
    xml_path = Path(xml_path)
    if not xml_path.exists():
        raise FileNotFoundError(f"Nmap XML not found: {xml_path}")

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as exc:
        raise ET.ParseError(f"Malformed XML in {xml_path}: {exc}") from exc

    root = tree.getroot()

    if root.tag != "nmaprun":
        raise ValueError(
            f"Expected root element <nmaprun>, got <{root.tag}>. " "Is this a valid Nmap XML file?"
        )

    # ---- scan-level metadata ------------------------------------------------
    args = root.get("args", "")
    nmap_version = root.get("version")
    if not nmap_version:
        raise ValueError("Missing 'version' attribute on <nmaprun>.")

    start_ts = root.get("start")
    if not start_ts:
        raise ValueError("Missing 'start' attribute on <nmaprun>.")

    finished_elem = root.find(".//runstats/finished")
    if finished_elem is None:
        raise ValueError("Missing <runstats/finished> element.")
    finish_ts = finished_elem.get("time")
    if not finish_ts:
        raise ValueError("Missing 'time' attribute on <finished>.")

    resolved_profile = profile if profile in ("quick", "full") else _detect_profile(args)
    subnet = _extract_subnet(args)

    # ---- hosts --------------------------------------------------------------
    hosts: list[dict[str, Any]] = []

    # <host> elements are direct children of <nmaprun>; <hosthint> elements
    # (present in full scans) are skipped because they carry no port data.
    for host_elem in root.findall("host"):
        ip: str | None = None
        mac: str | None = None
        vendor: str | None = None

        for addr_elem in host_elem.findall("address"):
            addr_type = addr_elem.get("addrtype", "")
            if addr_type == "ipv4":
                ip = addr_elem.get("addr")
            elif addr_type == "mac":
                mac = addr_elem.get("addr")
                vendor = addr_elem.get("vendor")  # may be absent → None

        if not ip:
            raise ValueError(f"Found a <host> element with no IPv4 address in {xml_path}.")

        # hostname – take the first PTR record if present
        hostname: str | None = None
        hostname_elem = host_elem.find("hostnames/hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name")

        # os_guess – nmap includes <osmatch name="…"> when -O is used
        os_guess: str | None = None
        osmatch_elem = host_elem.find(".//osmatch")
        if osmatch_elem is not None:
            os_guess = osmatch_elem.get("name")

        # ports
        ports: list[dict[str, Any]] = []
        for port_elem in host_elem.findall(".//port"):
            portid = port_elem.get("portid")
            protocol = port_elem.get("protocol")

            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else None

            service_elem = port_elem.find("service")
            service: str | None = None
            product: str | None = None
            version: str | None = None
            if service_elem is not None:
                service = service_elem.get("name")
                product = service_elem.get("product")
                version = service_elem.get("version")

            ports.append(
                {
                    "port": int(portid) if portid is not None else None,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                }
            )

        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "mac_randomised": _is_mac_randomised(mac),
                "hostname": hostname,
                "os_guess": os_guess,
                "ports": ports,
            }
        )

    return {
        "scan_id": str(uuid.uuid4()),
        "profile": resolved_profile,
        "subnet": subnet,
        "started_at": _ts_to_iso(start_ts),
        "finished_at": _ts_to_iso(finish_ts),
        "nmap_version": nmap_version,
        "hosts": hosts,
    }


# ---------------------------------------------------------------------------
# Script entry-point – regenerates tests/fixtures/lab-*.c1.json
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    _SCANNER_DIR = Path(__file__).parent
    _REPO_ROOT = _SCANNER_DIR.parents[1]
    _FIXTURES = _REPO_ROOT / "tests" / "fixtures"

    _SCANS = [
        ("quick", _FIXTURES / "lab-quick.xml", _FIXTURES / "lab-quick.c1.json"),
        ("full", _FIXTURES / "lab-full.xml", _FIXTURES / "lab-full.c1.json"),
    ]

    for _profile, _xml_path, _out_path in _SCANS:
        _result = parse_nmap_xml(_xml_path, profile=_profile)
        _out_path.write_text(
            json.dumps(_result, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(
            f"[{_profile:5}] wrote {_out_path.name}"
            f"  ({len(_result['hosts'])} hosts,"
            f" {sum(len(h['ports']) for h in _result['hosts'])} open ports)"
        )
