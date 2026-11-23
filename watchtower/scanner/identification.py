"""Explainable device identification using configurable scoring clues."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from watchtower.scanner.mac_helpers import is_randomised
from watchtower.scanner.models import Host, ScanResult, TypeGuess

DEFAULT_CLUES = Path(__file__).resolve().parents[2] / "rules" / "device_types.yaml"

# Numeric category codes preserve the existing C1/C2/API float contract.
# These are NOT estimated probabilities of correct identification.
CONFIDENCE_VALUES = {
    "unknown": 0.0,
    "low": 0.33,
    "medium": 0.67,
    "high": 1.0,
}
_LEVELS = tuple(CONFIDENCE_VALUES)
_MATCH_FIELDS = {
    "vendor_contains",
    "port",
    "ports_all",
    "ip_ends_with",
    "mac_randomised",
    "no_open_ports",
    "hostname_contains",
}


def confidence_label(value: float) -> str:
    """Return the readable category corresponding to a stored confidence code."""
    for label, code in CONFIDENCE_VALUES.items():
        if value == code:
            return label
    raise ValueError(f"Unknown device confidence code: {value}")


def load_clues(path: str | Path = DEFAULT_CLUES) -> list[dict[str, Any]]:
    """Load and validate device-type clues from a YAML file."""
    with Path(path).open(encoding="utf-8") as stream:
        clues = yaml.safe_load(stream)

    if not isinstance(clues, list) or not clues:
        raise ValueError("Device-type clues must be a non-empty list")

    for index, clue in enumerate(clues, start=1):
        if not isinstance(clue, dict):
            raise ValueError(f"Clue {index} must be an object")
        if not isinstance(clue.get("type"), str) or not clue["type"].strip():
            raise ValueError(f"Clue {index} needs a non-empty type")
        if not isinstance(clue.get("reason"), str) or not clue["reason"].strip():
            raise ValueError(f"Clue {index} needs a non-empty reason")
        points = clue.get("points")
        if type(points) is not int or points <= 0:
            raise ValueError(f"Clue {index} needs positive integer points")

        match_fields = set(clue) - {"type", "points", "reason"}
        if not match_fields or not match_fields <= _MATCH_FIELDS:
            raise ValueError(f"Clue {index} has missing or unsupported match fields")

        for field in ("vendor_contains", "hostname_contains"):
            if field in clue:
                values = clue[field]
                if isinstance(values, str):
                    values = [values]
                if (
                    not isinstance(values, list)
                    or not values
                    or any(not isinstance(value, str) or not value for value in values)
                ):
                    raise ValueError(f"Clue {index}: {field} needs non-empty text")

        for field in ("port", "ports_all"):
            if field in clue:
                values = clue[field]
                if type(values) is int:
                    values = [values]
                if (
                    not isinstance(values, list)
                    or not values
                    or any(type(value) is not int or not 1 <= value <= 65535 for value in values)
                ):
                    raise ValueError(f"Clue {index}: {field} needs valid port numbers")

        if "ip_ends_with" in clue and not isinstance(clue["ip_ends_with"], str):
            raise ValueError(f"Clue {index}: ip_ends_with needs text")
        for field in ("mac_randomised", "no_open_ports"):
            if field in clue and not isinstance(clue[field], bool):
                raise ValueError(f"Clue {index}: {field} needs a boolean")

    return clues


def _contains_any(text: str | None, patterns: str | list[str]) -> bool:
    if not text:
        return False
    if isinstance(patterns, str):
        patterns = [patterns]
    return any(pattern.casefold() in text.casefold() for pattern in patterns)


def _port_set(value: int | list[int]) -> set[int]:
    return {value} if isinstance(value, int) else set(value)


def _matches(
    clue: dict[str, Any], host: Host, *, profile: str, open_ports: set[int], private: bool
) -> bool:
    if "vendor_contains" in clue and not _contains_any(host.vendor, clue["vendor_contains"]):
        return False
    if "hostname_contains" in clue and not _contains_any(host.hostname, clue["hostname_contains"]):
        return False
    if "port" in clue and not (open_ports & _port_set(clue["port"])):
        return False
    if "ports_all" in clue and not _port_set(clue["ports_all"]) <= open_ports:
        return False
    if "ip_ends_with" in clue and not host.ip.endswith(clue["ip_ends_with"]):
        return False
    if "mac_randomised" in clue and private != clue["mac_randomised"]:
        return False
    if "no_open_ports" in clue:
        # A quick scan has no port data; absence of evidence isn't evidence of no ports.
        if profile != "full" or (not open_ports) != clue["no_open_ports"]:
            return False
    return True


def identify_host(
    host: Host, *, profile: str = "full", clues: list[dict[str, Any]] | None = None
) -> TypeGuess:
    """Score one host and return its most likely type, confidence code, and reasons.

    Quick-scan guesses are provisional; persistence must not replace a prior
    full-scan identification with one of these guesses.
    """
    if profile not in ("quick", "full"):
        raise ValueError(f"Invalid scan profile: {profile}")
    if clues is None:
        clues = load_clues()

    open_ports = {port.port for port in host.ports if port.state == "open"}
    try:
        private = host.mac_randomised or is_randomised(host.mac)
    except ValueError:
        private = host.mac_randomised

    scores: dict[str, int] = defaultdict(int)
    reasons: dict[str, list[str]] = defaultdict(list)
    for clue in clues:
        if _matches(clue, host, profile=profile, open_ports=open_ports, private=private):
            device_type = clue["type"]
            scores[device_type] += clue["points"]
            reasons[device_type].append(clue["reason"])

    if not scores:
        return TypeGuess(type="unknown", confidence=CONFIDENCE_VALUES["unknown"], reasons=[])

    # Stable tie-breaking uses the order of clues in the YAML file.
    winning_type = max(scores, key=lambda device_type: scores[device_type])
    winning_score = scores[winning_type]
    if winning_score >= 5:
        level = "high"
    elif winning_score >= 3:
        level = "medium"
    else:
        level = "low"

    others = [score for name, score in scores.items() if name != winning_type]
    if others and winning_score - max(others) <= 1:
        level = _LEVELS[max(0, _LEVELS.index(level) - 1)]

    return TypeGuess(
        type=winning_type,
        confidence=CONFIDENCE_VALUES[level],
        reasons=reasons[winning_type],
    )


def identify_scan(scan: ScanResult) -> list[TypeGuess]:
    """Return guesses in the same order as scan.hosts without changing the scan."""
    clues = load_clues()
    return [identify_host(host, profile=scan.profile, clues=clues) for host in scan.hosts]
