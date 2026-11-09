"""WT-97: the red-flag rules follow contract C3 and cover the lab inventory (C6)."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"id", "title", "severity", "match", "explanation", "fix"}
SEVERITIES = {"high", "medium", "low", "info"}
MATCH_KEYS = {"port", "service", "product", "version_below"}


def _load(path: str):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


RULES = _load("rules/red_flags.yaml")


def test_first_ten_rules_with_unique_ids() -> None:
    ids = [rule["id"] for rule in RULES]
    assert len(ids) == 10
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule["id"])
def test_rule_follows_c3(rule: dict) -> None:
    assert REQUIRED <= rule.keys()
    assert rule["id"].startswith("RF-")
    assert rule["severity"] in SEVERITIES
    assert rule["match"] and set(rule["match"]) <= MATCH_KEYS
    assert all(
        isinstance(rule[key], str) and rule[key].strip() for key in ("title", "explanation", "fix")
    )


def test_every_finding_the_lab_expects_has_a_rule() -> None:
    expected = {
        finding
        for device in _load("lab/inventory.yaml")["devices"]
        for finding in device.get("expected_findings") or []
    }
    assert expected <= {rule["id"] for rule in RULES}


def test_vuln_versions_is_a_list() -> None:
    assert isinstance(_load("rules/vuln_versions.yaml"), list)
