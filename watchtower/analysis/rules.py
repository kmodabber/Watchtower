"""Red-flag rules engine (WT-65, WT-FR-14, PRD T-13).

Turns the rules in rules/red_flags.yaml (contract C3) into findings for one device.
Only open-port checks: no NSE scripts (D1). When unsure, raise nothing: a missing
finding beats a wrong one.
"""

from pathlib import Path
from typing import Any

import yaml

from watchtower.scanner.models import Finding, Host, Port

DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules" / "red_flags.yaml"


def load_rules(path: str | Path = DEFAULT_RULES) -> list[dict[str, Any]]:
    """Read the YAML file and return the list of rules (dicts in the C3 shape)."""
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def _port_matches(port: Port, match: dict[str, Any]) -> bool:
    """True if every key in a rule's ``match`` holds for this one port."""
    if "version_below" in match:
        return False  # version checks come in Stage 4 (WT-FR-18); raise nothing until then
    checks = {"port": port.port, "service": port.service, "product": port.product}
    return all(checks[key] == value for key, value in match.items())


def evaluate(host: Host, device_type: str | None, rules: list[dict[str, Any]]) -> list[Finding]:
    """Return one Finding for each rule this host triggers.

    - ``match`` keys are checked by name (port, service, product); all must hold on
      the same open port. A rule with ``version_below`` is skipped for now.
    - ``device_types``: the rule applies only to those types. If ``device_type`` is
      None (unknown or unsure), the rule is skipped.
    """
    findings: list[Finding] = []
    open_ports = [p for p in host.ports if p.state == "open"]
    for rule in rules:
        allowed = rule.get("device_types")
        if allowed is not None and device_type not in allowed:
            continue
        match = rule.get("match") or {}
        if not match:
            continue
        hit = next((p for p in open_ports if _port_matches(p, match)), None)
        if hit is None:
            continue
        findings.append(
            Finding(
                rule_id=rule["id"],
                severity=rule["severity"],
                title=rule["title"],
                explanation=" ".join(str(rule["explanation"]).split()),
                fix=" ".join(str(rule["fix"]).split()),
                port=hit.port,
            )
        )
    return findings
