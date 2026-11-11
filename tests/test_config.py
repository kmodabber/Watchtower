from pathlib import Path

import pytest

from watchtower.config import ConfigError, load_config

GOOD_TOML = """\
interface = "eth0"
db_path = "var/test.db"
quick_interval_min = 5
full_interval_min = 15
dashboard_url = "http://localhost:8000"
discord_webhook = ""
"""

REQUIRED_KEYS = [
    "interface",
    "db_path",
    "quick_interval_min",
    "full_interval_min",
    "dashboard_url",
]


def write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "watchtower.toml"
    path.write_text(text)
    return path


def drop_key(text: str, key: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.startswith(key))


def test_dev_config_loads() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config = load_config(repo_root / "lab/watchtower.dev.toml")
    assert config.interface == "eth0"
    assert config.quick_interval_min == 5
    assert config.full_interval_min == 15
    assert config.discord_webhook == ""


@pytest.mark.parametrize("key", REQUIRED_KEYS)
def test_missing_key_fails_loudly(tmp_path: Path, key: str) -> None:
    path = write_config(tmp_path, drop_key(GOOD_TOML, key))
    with pytest.raises(ConfigError, match=key):
        load_config(path)


def test_bool_is_not_an_int(tmp_path: Path) -> None:
    text = GOOD_TOML.replace("quick_interval_min = 5", "quick_interval_min = true")
    with pytest.raises(ConfigError, match="quick_interval_min"):
        load_config(write_config(tmp_path, text))


def test_webhook_not_shown_in_repr(tmp_path: Path) -> None:
    text = GOOD_TOML.replace('discord_webhook = ""', 'discord_webhook = "dummy-secret"')
    config = load_config(write_config(tmp_path, text))
    assert "dummy-secret" not in repr(config)
