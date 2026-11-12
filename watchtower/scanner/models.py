"""Contract C1: The shapes the scan engine returns, as dataclasses.

Every class converts to and from plain dicts and JSON. Quick scans have empty
``ports``. ``os_guess`` is always empty: the full profile has no -O flag
(decision D4). to_dict is written by hand instead of dataclasses.asdict since
asdict leaves datetime objects as-is and json.dumps cannot serialise them.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Self

PROFILES = ("quick", "full")
SEVERITIES = ("high", "medium", "low", "info")


class ModelError(ValueError):
    """Data does not fit a C1 shape."""


def _need(data: dict[str, Any], key: str, where: str) -> Any:
    try:
        return data[key]
    except KeyError as e:
        raise ModelError(f"{where}: missing key '{key}'") from e


def _parse_time(value: Any, key: str, where: str) -> datetime:
    if not isinstance(value, str):
        raise ModelError(f"{where}: '{key}' must be an ISO-8601 string")
    try:
        return datetime.fromisoformat(value)
    except ValueError as e:
        raise ModelError(f"{where}: '{key}' is not a valid ISO-8601 time") from e


class _JsonMixin:
    """Shared JSON helpers built on each class's to_dict / from_dict."""

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict of JSON-safe values. Each subclass implements this."""
        raise NotImplementedError

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """Return a plain dict of JSON-safe values. Each subclass implements this."""
        raise NotImplementedError

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, text: str) -> Self:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ModelError(f"{cls.__name__}: invalid JSON: {e}") from e
        if not isinstance(data, dict):
            raise ModelError(f"{cls.__name__}: JSON must be an object")
        return cls.from_dict(data)


@dataclass
class Port(_JsonMixin):
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ModelError("Port: 'port' must be an integer")

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            port=_need(data, "port", "Port"),
            protocol=_need(data, "protocol", "Port"),
            state=_need(data, "state", "Port"),
            service=data.get("service"),
            product=data.get("product"),
            version=data.get("version"),
        )


@dataclass
class Host(_JsonMixin):
    ip: str
    mac: str | None = None
    vendor: str | None = None
    mac_randomised: bool = False
    hostname: str | None = None
    os_guess: str | None = None  # always empty (D4: no -O flag)
    ports: list[Port] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "mac_randomised": self.mac_randomised,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "ports": [port.to_dict() for port in self.ports],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            ip=_need(data, "ip", "Host"),
            mac=data.get("mac"),
            vendor=data.get("vendor"),
            mac_randomised=_need(data, "mac_randomised", "Host"),
            hostname=data.get("hostname"),
            os_guess=data.get("os_guess"),
            ports=[Port.from_dict(p) for p in _need(data, "ports", "Host")],
        )


@dataclass
class ScanResult(_JsonMixin):
    scan_id: str
    profile: str
    subnet: str
    started_at: datetime
    finished_at: datetime
    nmap_version: str
    hosts: list[Host] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.profile not in PROFILES:
            raise ModelError(f"ScanResult: profile must be one of {PROFILES}")
        if not isinstance(self.subnet, str) or not self.subnet:
            raise ModelError("ScanResult: 'subnet' must be a non-empty string")
        for name in ("started_at", "finished_at"):
            if getattr(self, name).tzinfo is None:
                raise ModelError(f"ScanResult: '{name}' must include a timezone (UTC)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "profile": self.profile,
            "subnet": self.subnet,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "nmap_version": self.nmap_version,
            "hosts": [host.to_dict() for host in self.hosts],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        where = "ScanResult"
        return cls(
            scan_id=_need(data, "scan_id", where),
            profile=_need(data, "profile", where),
            subnet=_need(data, "subnet", where),
            started_at=_parse_time(_need(data, "started_at", where), "started_at", where),
            finished_at=_parse_time(_need(data, "finished_at", where), "finished_at", where),
            nmap_version=_need(data, "nmap_version", where),
            hosts=[Host.from_dict(h) for h in _need(data, "hosts", where)],
        )


@dataclass
class TypeGuess(_JsonMixin):
    type: str
    confidence: float  # 0.0 to 1.0 (based on schema_v0)
    reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, int | float):
            raise ModelError("TypeGuess: confidence must be a number")
        if not 0.0 <= self.confidence <= 1.0:
            raise ModelError("TypeGuess: confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "confidence": self.confidence, "reasons": list(self.reasons)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            type=_need(data, "type", "TypeGuess"),
            confidence=_need(data, "confidence", "TypeGuess"),
            reasons=list(_need(data, "reasons", "TypeGuess")),
        )


@dataclass
class Finding(_JsonMixin):
    rule_id: str
    severity: str
    title: str
    explanation: str
    fix: str
    port: int | None = None

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ModelError(f"Finding: severity must be one of {SEVERITIES}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "explanation": self.explanation,
            "fix": self.fix,
            "port": self.port,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        where = "Finding"
        return cls(
            rule_id=_need(data, "rule_id", where),
            severity=_need(data, "severity", where),
            title=_need(data, "title", where),
            explanation=_need(data, "explanation", where),
            fix=_need(data, "fix", where),
            port=data.get("port"),
        )
