"""Subnet guardrail (WT-FR-23, T-05): what Watchtower may scan.

Every scan path calls this before Nmap runs. The target is always computed from
the host's own interface, never typed by a user. It must be private
(10/8, 172.16/12 or 192.168/16) and no larger than a /23. Anything else is
refused with GuardrailError and a log line.
"""

import ipaddress
import json
import logging
import re
import subprocess
from ipaddress import IPv4Address, IPv4Network

logger = logging.getLogger(__name__)

# The only ranges a scan may ever target.
ALLOWED_RANGES: tuple[IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
MIN_PREFIX_LENGTH = 23  # a /23 is the largest network allowed
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_IP_TIMEOUT_SECONDS = 10


class GuardrailError(ValueError):
    """A scan target is not allowed. Subclasses ValueError so existing callers still work."""


def _refuse(message: str) -> GuardrailError:
    logger.warning("Scan refused: %s", message)
    return GuardrailError(message)


def validate_target(network: IPv4Network, own_ip: IPv4Address) -> tuple[IPv4Network, IPv4Address]:
    """Return ``(network, own_ip)`` if the target is allowed, else raise GuardrailError."""
    if not any(network.subnet_of(allowed) for allowed in ALLOWED_RANGES):
        raise _refuse(f"{network} is not a private network (10/8, 172.16/12, 192.168/16)")
    if network.prefixlen < MIN_PREFIX_LENGTH:
        raise _refuse(f"{network} is larger than a /{MIN_PREFIX_LENGTH}")
    if own_ip not in network:
        raise _refuse(f"{network} does not contain this machine's address {own_ip}")
    return network, own_ip


def scope_from_interface_address(address: str) -> tuple[IPv4Network, IPv4Address]:
    """Turn an interface address such as ``"172.28.0.10/24"`` into an allowed scan scope."""
    try:
        interface = ipaddress.IPv4Interface(address)
    except ValueError as exc:
        raise _refuse(f"{address!r} is not an IPv4 interface address") from exc
    return validate_target(interface.network, interface.ip)


def interface_address_from_ip_json(output: str, interface: str) -> str:
    """Read ``ip -j -4 addr show`` output and return the first ``address/prefix``."""
    try:
        entries = json.loads(output)
        info = entries[0]["addr_info"][0]
        return f"{info['local']}/{info['prefixlen']}"
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise _refuse(f"no IPv4 address found on interface {interface!r}") from exc


def scan_scope(interface: str) -> tuple[IPv4Network, IPv4Address]:
    """Compute the scan scope from a configured interface name, or raise GuardrailError."""
    if not _INTERFACE_NAME.match(interface):
        raise _refuse(f"{interface!r} is not a valid interface name")
    try:
        completed = subprocess.run(
            ["ip", "-j", "-4", "addr", "show", "dev", interface],
            capture_output=True,
            text=True,
            timeout=_IP_TIMEOUT_SECONDS,
            shell=False,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _refuse(f"could not read interface {interface!r}: {exc}") from exc
    address = interface_address_from_ip_json(completed.stdout, interface)
    return scope_from_interface_address(address)
