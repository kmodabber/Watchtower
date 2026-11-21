from watchtower.scanner.models import Finding, Host
import yaml

def load_rules(path="rules/red_flags.yaml") -> list[dict]:
    """Read the YAML file and return the list of rules.

    Each rule is a dict with keys: id, title, severity, match,
    explanation, fix, references, and optionally device_types.

    Example::

        [
            {
                "id": "RF-TELNET",
                "title": "Telnet is open",
                "severity": "high",
                "match": {"port": 23},
                ...
            },
            ...
        ]
    """
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def evaluate(host: Host, device_type: str | None, rules: list[dict]) -> list[Finding]:
    """Return one Finding for each rule this host triggers.

    Matching logic (Stage 1 only — product/version_below ignored):
    - match.port:    any open port whose port number equals the value.
    - match.service: any open port whose service name equals the value.
    - device_types:  if present, device_type must be in the list.
                     If device_type is None, the rule is skipped.
    When uncertain, the rule is skipped — a missing finding beats a wrong one.
    """
    findings: list[Finding] = []

    for rule in rules:
        # --- device_types filter ---
        allowed_types: list[str] | None = rule.get("device_types")
        if allowed_types is not None:
            if device_type is None or device_type not in allowed_types:
                continue

        # --- port/service (or other string) matching ---
        match: dict = rule.get("match", {})
        matched_port: int | None = None
        match_key: str | None = next((k for k in match if k != "port"), None)

        if "port" in match:
            target_port: int = match["port"]
            for p in host.ports:
                if p.port == target_port:
                    matched_port = p.port
                    break

        elif match_key:
            target_value: str = match[match_key]
            for p in host.ports:
                if getattr(p, match_key, None) == target_value:
                    matched_port = p.port
                    break

        else:
            continue

        if matched_port is None:
            continue

        findings.append(Finding(
            rule_id=rule["id"],
            severity=rule["severity"],
            title=rule["title"],
            explanation=rule["explanation"],
            fix=rule["fix"],
            port=matched_port,
        ))

    return findings
