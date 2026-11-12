"""Load Watchtower settings from a TOML file (stdlib ``tomllib``).
A missing or wrong-typed key fails loudly.
"""

import logging
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
CONFIG_ENV_VAR = "WATCHTOWER_CONFIG"
DEFAULT_CONFIG_PATH = Path("watchtower.toml")


class ConfigError(Exception):
    """The config file is missing, unreadable, or has a missing or bad key."""


@dataclass(frozen=True)
class Config:
    interface: str
    db_path: Path
    quick_interval_min: int
    full_interval_min: int
    dashboard_url: str
    discord_webhook: str = field(default="", repr=False)  # webhook not visible in repr


def resolve_config_path(path: str | Path | None = None) -> Path:
    """Resolve the config file path from the given path, environment variable, or default."""
    if path is not None:
        return Path(path)
    return Path(os.environ.get(CONFIG_ENV_VAR, DEFAULT_CONFIG_PATH))


def _read_toml(path: Path) -> dict[str, Any]:
    """Read a TOML file and return its contents as a dictionary."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError as e:
        raise ConfigError(f"Config file not found: {path}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"Failed to parse config file {path}: {e}") from e


def _required(data: dict[str, Any], key: str, kind: type, path: Path) -> Any:
    """Get a required value from the data dictionary."""
    if key not in data:
        raise ConfigError(f"Missing required key '{key}' in {path}")
    value = data[key]
    # book check: True in Python is an instance of int
    if not isinstance(value, kind) or isinstance(value, bool):
        raise ConfigError(f"Key '{key}' in {path} must be {kind.__name__}")
    if kind is str and not value.strip():
        raise ConfigError(f"Key '{key}' in {path} must not be empty")
    if kind is int and value <= 0:
        raise ConfigError(f"Key '{key}' in {path} must be greater than zero")
    return value


def load_config(path: str | Path | None = None) -> Config:
    """Read and validate the config file, or raise ConfigError."""
    config_path = resolve_config_path(path)
    data = _read_toml(config_path)

    webhook = data.get("discord_webhook", "")
    if not isinstance(webhook, str):
        raise ConfigError(f"Key 'discord_webhook' in {config_path} must be str")
    config = Config(
        interface=_required(data, "interface", str, config_path),
        db_path=Path(_required(data, "db_path", str, config_path)),
        quick_interval_min=_required(data, "quick_interval_min", int, config_path),
        full_interval_min=_required(data, "full_interval_min", int, config_path),
        dashboard_url=_required(data, "dashboard_url", str, config_path),
        discord_webhook=webhook,
    )
    log.info("Loaded config from %s", config_path)
    return config
