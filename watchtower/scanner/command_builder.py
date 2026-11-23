"""The only place Watchtower builds an Nmap command (WT-FR-12, T-11, WT-76).

``build_command`` returns argv for ``subprocess.run(..., shell=False)``.
It never returns a shell string. Commands are built from the two fixed
profile lists only; there is no way to pass extra flags.

``validate_command`` allows only the exact argv for a known profile, network
and exclude IP. Anything else is refused and logged. The NSE allowlist is empty
(decision D1), so no script can run. Adding a script later needs Kam's OK and
an entry in doc 02. Public-range and subnet-size limits are WT-74.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import NoReturn

from watchtower.scanner.ports import FULL_SCAN_PORTS

logger = logging.getLogger(__name__)

# Decision D1: no NSE scripts until Kam approves one and it is listed in doc 02.
# Exact matching already refuses every script flag while this stays empty.
SCRIPT_ALLOWLIST: frozenset[str] = frozenset()

# Gentle profiles. Nothing else may be appended, including --script.
_PROFILE_FLAGS: dict[str, tuple[str, ...]] = {
    "quick": ("-sn", "--privileged"),
    "full": (
        "-sS",
        "-sV",
        "--version-light",
        "-p",
        FULL_SCAN_PORTS,  # Nmap's top 1000 plus MQTT (1883, 8883): see ports.py
        "-T3",
        "--max-rate",
        "100",
        "--host-timeout",
        "5m",
        "--privileged",
    ),
}

PROFILES: tuple[str, ...] = tuple(_PROFILE_FLAGS)


class CommandNotAllowed(ValueError):
    """The Nmap argv is not one of the two approved profile commands."""


def _refuse(message: str) -> NoReturn:
    logger.error("Nmap command refused: %s", message)
    raise CommandNotAllowed(message)


def require_argv_token(name: str, value: object) -> str:
    """Require one argv element: non-empty, no leading dash, no whitespace."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    if value.startswith("-") or any(char.isspace() for char in value):
        raise ValueError(f"{name} must be a host or subnet, not nmap options")
    return value


def _approved_args(profile: str, network: str, exclude_ip: str) -> list[str]:
    """Return the only allowed arguments after argv[0], or refuse the inputs."""
    if not isinstance(profile, str) or profile not in _PROFILE_FLAGS:
        _refuse(f"profile must be 'quick' or 'full', got {profile!r}")
    try:
        if not isinstance(network, str):
            raise ValueError
        # strict=False: a host address with a prefix is still a valid Nmap target.
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        _refuse(f"network must be an IP network, got {network!r}")
    try:
        if not isinstance(exclude_ip, str):
            raise ValueError
        ipaddress.ip_address(exclude_ip)
    except ValueError:
        _refuse(f"exclude_ip must be a single IP address, got {exclude_ip!r}")
    return [*_PROFILE_FLAGS[profile], "-oX", "-", "--exclude", exclude_ip, network]


def validate_command(argv: object, profile: str, network: str, exclude_ip: str) -> None:
    """Refuse any argv that is not the approved command for these inputs.

    ``argv[0]`` may be ``nmap`` or a custom binary path. ``argv[1:]`` must
    match the profile flags, ``-oX -``, ``--exclude``, ``exclude_ip`` and
    ``network`` exactly.

    Raises
    ------
    CommandNotAllowed
        Unknown profile, invalid network or exclude_ip, or any other argv.
        The refusal is logged. No command is run.
    """
    expected = _approved_args(profile, network, exclude_ip)
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(part, str) and part for part in argv)
    ):
        _refuse("command must be a non-empty list of strings")
    if argv[1:] != expected:
        _refuse(f"arguments are not the approved {profile} command: {argv[1:]!r}")


def build_command(profile: str, network: str, exclude_ip: str) -> list[str]:
    """Build the Nmap argv for ``profile``.

    ``network`` and ``exclude_ip`` each become one argument. ``exclude_ip``
    is required and is always passed as ``--exclude``.

    Raises
    ------
    CommandNotAllowed
        Unknown profile, or a network / exclude_ip that does not parse.
        The refusal is logged. No command list is returned in that case.
    """
    return ["nmap", *_approved_args(profile, network, exclude_ip)]
