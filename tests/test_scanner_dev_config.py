"""WT-95: smoke-check the committed scanner dev configuration."""

import tomllib
from pathlib import Path


def test_scanner_dev_config_points_to_lab_interface() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((repo_root / "lab/watchtower.dev.toml").read_text())
    assert config["interface"] == "eth0"
    assert config["quick_interval_min"] == 5
    assert config["full_interval_min"] == 15
    assert not config["discord_webhook"]


def test_scanner_dockerfile_uses_prd_base_image() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    text = (repo_root / "lab/Dockerfile.scanner").read_text()
    assert "FROM python:3.12-slim" in text
    assert "nmap iproute2" in text
