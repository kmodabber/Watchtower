"""WT-76 / TC-08: only the two exact profile commands are allowed.

These tests never start Nmap and never touch the network. Public-range and
subnet-size refusals are WT-74, not this file.
"""

from __future__ import annotations

import logging
import subprocess

import pytest

from watchtower.scanner import scan_engine
from watchtower.scanner.command_builder import (
    SCRIPT_ALLOWLIST,
    CommandNotAllowed,
    build_command,
    validate_command,
)
from watchtower.scanner.scan_engine import NmapEngine

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


def _swap(old: str, new: str) -> list[str]:
    return [new if part == old else part for part in FULL_COMMAND]


TAMPERED_COMMANDS = {
    "max-rate": _swap("100", "100000"),
    "top-ports": _swap("1000", "65535"),
    "output-file": _swap("-", "/tmp/out.xml"),
    "removed-exclude": [part for part in FULL_COMMAND if part not in ("--exclude", EXCLUDE_IP)],
    "bare-nmap-net": ["nmap", NETWORK],
    "extra-target": [*FULL_COMMAND, "8.8.8.8"],
    "repeated-oX": [*FULL_COMMAND[:-1], "-oX", "-", NETWORK],
    "bare-dash": [*FULL_COMMAND, "-"],
    "sCV": [*FULL_COMMAND, "-sCV"],
    "abbreviated-script": [*FULL_COMMAND, "--scr=vuln"],
    "script": [*FULL_COMMAND, "--script", "vuln"],
    "script-equals": [*FULL_COMMAND, "--script=default"],
    "script-in-middle": [*FULL_COMMAND[:-1], "--script", "http-enum", NETWORK],
    "os-detection": [*FULL_COMMAND, "-O"],
    "aggressive": [*FULL_COMMAND, "-A"],
    "other-network": _swap(NETWORK, "172.28.1.0/24"),
    "other-exclude": _swap(EXCLUDE_IP, "172.28.0.7"),
}


@pytest.mark.parametrize(
    ("profile", "expected"),
    [("quick", QUICK_COMMAND), ("full", FULL_COMMAND)],
)
def test_approved_profile_commands_pass(profile: str, expected: list[str]) -> None:
    assert build_command(profile, NETWORK, EXCLUDE_IP) == expected
    validate_command(expected, profile, NETWORK, EXCLUDE_IP)
    validate_command(["/opt/nmap", *expected[1:]], profile, NETWORK, EXCLUDE_IP)


def test_script_allowlist_is_empty() -> None:
    assert SCRIPT_ALLOWLIST == frozenset()


def test_profiles_are_not_interchangeable() -> None:
    with pytest.raises(CommandNotAllowed):
        validate_command(QUICK_COMMAND, "full", NETWORK, EXCLUDE_IP)


@pytest.mark.parametrize("command", TAMPERED_COMMANDS.values(), ids=TAMPERED_COMMANDS.keys())
def test_changed_command_is_refused(command: list[str], caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.ERROR)
    with pytest.raises(CommandNotAllowed, match="approved"):
        validate_command(command, "full", NETWORK, EXCLUDE_IP)
    assert "Nmap command refused" in caplog.text


@pytest.mark.parametrize("argv", [None, [], "nmap -sn", tuple(QUICK_COMMAND), ["nmap", 1]])
def test_malformed_argv_is_refused(argv: object, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.ERROR)
    with pytest.raises(CommandNotAllowed, match="list of strings"):
        validate_command(argv, "quick", NETWORK, EXCLUDE_IP)
    assert "Nmap command refused" in caplog.text


@pytest.mark.parametrize("profile", ["", "deep", "QUICK", "full ", None, ["quick"]])
def test_unknown_profile_is_refused(profile: object, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.ERROR)
    with pytest.raises(CommandNotAllowed, match="profile"):
        validate_command(QUICK_COMMAND, profile, NETWORK, EXCLUDE_IP)  # type: ignore[arg-type]
    with pytest.raises(CommandNotAllowed, match="profile"):
        build_command(profile, NETWORK, EXCLUDE_IP)  # type: ignore[arg-type]
    assert "Nmap command refused" in caplog.text


@pytest.mark.parametrize(
    "exclude_ip",
    ["scanner.local", "172.28.0.6,172.28.0.7", "172.28.0.6/32", "", "-sS", None],
)
def test_bad_exclude_ip_is_refused(exclude_ip: object, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.ERROR)
    with pytest.raises(CommandNotAllowed, match="exclude_ip"):
        validate_command(QUICK_COMMAND, "quick", NETWORK, exclude_ip)  # type: ignore[arg-type]
    with pytest.raises(CommandNotAllowed, match="exclude_ip"):
        build_command("quick", NETWORK, exclude_ip)  # type: ignore[arg-type]
    assert "Nmap command refused" in caplog.text


@pytest.mark.parametrize(
    "network",
    ["lab.local", "172.28.0.0/33", "172.28.0.0/24,8.8.8.8", "", "-sn", None],
)
def test_bad_network_is_refused(network: object, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.ERROR)
    with pytest.raises(CommandNotAllowed, match="network"):
        validate_command(QUICK_COMMAND, "quick", network, EXCLUDE_IP)  # type: ignore[arg-type]
    with pytest.raises(CommandNotAllowed, match="network"):
        build_command("quick", network, EXCLUDE_IP)  # type: ignore[arg-type]
    assert "Nmap command refused" in caplog.text


def _forbid_process(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    ran: list[object] = []

    def fail_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        ran.append(True)
        raise AssertionError("Nmap must not be started for a refused command")

    monkeypatch.setattr(scan_engine.subprocess, "run", fail_run)
    return ran


@pytest.mark.parametrize("command", TAMPERED_COMMANDS.values(), ids=TAMPERED_COMMANDS.keys())
def test_nmap_engine_refuses_changed_command_and_does_not_run(
    command: list[str], monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """TC-08: a command changed after build_command is still refused; no packet sent."""
    ran = _forbid_process(monkeypatch)
    monkeypatch.setattr(scan_engine, "build_command", lambda *_args: list(command))
    caplog.set_level(logging.ERROR)
    with pytest.raises(CommandNotAllowed):
        NmapEngine(exclude_ip=EXCLUDE_IP).run("full", NETWORK)
    assert ran == []
    assert "Nmap command refused" in caplog.text


@pytest.mark.parametrize(
    ("profile", "network", "exclude_ip", "message"),
    [
        ("deep", NETWORK, EXCLUDE_IP, "profile"),
        ("quick", "lab.local", EXCLUDE_IP, "network"),
        ("quick", NETWORK, "scanner.local", "exclude_ip"),
        ("quick", NETWORK, "172.28.0.6,172.28.0.7", "exclude_ip"),
        ("quick", NETWORK, None, "exclude_ip"),
    ],
)
def test_nmap_engine_refuses_bad_inputs_and_does_not_run(
    profile: str,
    network: str,
    exclude_ip: str | None,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    ran = _forbid_process(monkeypatch)
    caplog.set_level(logging.ERROR)
    with pytest.raises(CommandNotAllowed, match=message):
        NmapEngine(exclude_ip=exclude_ip).run(profile, network)
    assert ran == []
    assert "Nmap command refused" in caplog.text
