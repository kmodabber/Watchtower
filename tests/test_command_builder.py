"""WT-FR-12: build_command is the only Nmap argv constructor.

These tests never start Nmap and never touch the network.
"""

import pytest

from watchtower.scanner.command_builder import build_command

NETWORK = "172.28.0.0/24"
EXCLUDE_IP = "172.28.0.6"

QUICK_COMMAND = [
    "nmap",
    "-sn",
    "--privileged",
    "-oX",
    "-",
    "--exclude",
    EXCLUDE_IP,
    NETWORK,
]

FULL_COMMAND = [
    "nmap",
    "-sS",
    "-sV",
    "--version-light",
    "--top-ports",
    "1000",
    "-T3",
    "--max-rate",
    "100",
    "--host-timeout",
    "5m",
    "--privileged",
    "-oX",
    "-",
    "--exclude",
    EXCLUDE_IP,
    NETWORK,
]


@pytest.mark.parametrize(
    ("profile", "expected"),
    [("quick", QUICK_COMMAND), ("full", FULL_COMMAND)],
)
def test_build_command_matches_the_gentle_profile(profile: str, expected: list[str]) -> None:
    command = build_command(profile, NETWORK, EXCLUDE_IP)
    assert command == expected
    assert isinstance(command, list)
    assert all(isinstance(part, str) for part in command)
    assert "--script" not in command
    assert not any(part.startswith("--script") for part in command)


@pytest.mark.parametrize(
    ("network", "exclude_ip"),
    [("10.0.0.0/24", "10.0.0.2"), ("192.168.1.0/24", "192.168.1.50")],
)
def test_network_and_exclude_ip_are_single_trailing_args(network: str, exclude_ip: str) -> None:
    command = build_command("full", network, exclude_ip)
    assert command[-3:] == ["--exclude", exclude_ip, network]
    assert command[:4] == ["nmap", "-sS", "-sV", "--version-light"]
    assert "--script" not in command


@pytest.mark.parametrize("profile", ["", "deep", "QUICK", "full ", None])
def test_unknown_profile_raises(profile: object) -> None:
    with pytest.raises(ValueError, match="profile"):
        build_command(profile, NETWORK, EXCLUDE_IP)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "network",
    ["", "   ", "-sn", "--privileged", "172.28.0.0/24 extra", "172.28.0.0/24\nmore", None],
)
def test_invalid_network_raises_and_builds_no_command(network: object) -> None:
    with pytest.raises(ValueError, match="network"):
        build_command("quick", network, EXCLUDE_IP)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "exclude_ip",
    ["", "   ", "-sS", "--exclude", "172.28.0.6 172.28.0.7", "172.28.0.6\tnext", None],
)
def test_invalid_exclude_ip_raises_and_builds_no_command(exclude_ip: object) -> None:
    with pytest.raises(ValueError, match="exclude_ip"):
        build_command("quick", NETWORK, exclude_ip)  # type: ignore[arg-type]


def test_build_command_rejects_extra_arguments() -> None:
    with pytest.raises(TypeError):
        build_command(  # type: ignore[call-arg]
            "quick",
            NETWORK,
            EXCLUDE_IP,
            "--script",
            "vuln",
        )
