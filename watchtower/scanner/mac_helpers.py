"""Normalize MAC addresses and label locally administered addresses."""

import re
from dataclasses import replace

from watchtower.scanner.models import Host

PRIVATE_ADDRESS_VENDOR = "Private address (randomised MAC)"
_HEX_MAC = re.compile(r"[0-9a-fA-F]{12}\Z")


def normalise(mac: str | None) -> str | None:
    """Return a MAC as six lowercase colon-separated octets, or None if absent."""
    if mac is None:
        return None
    if not isinstance(mac, str):
        raise ValueError("MAC address must be a string or None")

    compact = mac.strip().replace(":", "").replace("-", "").replace(".", "")
    if _HEX_MAC.fullmatch(compact) is None:
        raise ValueError(f"Invalid MAC address: {mac!r}")

    compact = compact.lower()
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


def is_randomised(mac: str | None) -> bool:
    """Use the locally administered bit as a private-address heuristic."""
    canonical = normalise(mac)
    return canonical is not None and bool(int(canonical[:2], 16) & 0b10)


def label_host_mac(host: Host) -> Host:
    """Return a host with normalized MAC, privacy flag, and vendor label."""
    mac = normalise(host.mac)
    private = is_randomised(mac)
    vendor = PRIVATE_ADDRESS_VENDOR if private else host.vendor
    return replace(host, mac=mac, mac_randomised=private, vendor=vendor)
