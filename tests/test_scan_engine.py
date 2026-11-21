"""WT-FR-13: FakeEngine returns saved WT-55 scans in the C1 shape.

NmapEngine is only checked where a stand-in subprocess returns XML on stdout.
Nothing here starts Nmap or touches the network. The lab test (WT-54) covers
the real binary.
"""

import json
import logging
import subprocess
import uuid
from pathlib import Path

import pytest

from watchtower.scanner import scan_engine
from watchtower.scanner.command_builder import build_command
from watchtower.scanner.models import ScanResult
from watchtower.scanner.nmap_parser import parse_nmap_xml
from watchtower.scanner.scan_engine import FakeEngine, NmapEngine, ScanEngine, ScanFailed

FIXTURES = Path(__file__).resolve().parent / "fixtures"
C1_KEYS = {
    "scan_id",
    "profile",
    "subnet",
    "started_at",
    "finished_at",
    "nmap_version",
    "hosts",
}
HOST_KEYS = {"ip", "mac", "vendor", "mac_randomised", "hostname", "os_guess", "ports"}
PORT_KEYS = {"port", "protocol", "state", "service", "product", "version"}


def _as_dict(result: ScanResult | dict) -> dict:
    return result.to_dict() if isinstance(result, ScanResult) else result


def _without_scan_id(result: ScanResult | dict) -> dict:
    # scan_id is a fresh UUID on every parse, so it can't be compared.
    return {key: value for key, value in _as_dict(result).items() if key != "scan_id"}


def _assert_c1(result: ScanResult, profile: str) -> None:
    assert isinstance(result, ScanResult)
    assert set(result.to_dict()) == C1_KEYS
    assert result.profile == profile
    uuid.UUID(result.scan_id)
    assert uuid.UUID(result.scan_id).version == 4
    assert result.hosts
    for host in result.hosts:
        assert set(host.to_dict()) == HOST_KEYS
        for port in host.ports:
            assert set(port.to_dict()) == PORT_KEYS


@pytest.mark.parametrize("profile", ["quick", "full"])
def test_fake_engine_returns_saved_c1(profile: str) -> None:
    engine = FakeEngine(FIXTURES)
    result = engine.run(profile, "172.28.0.0/24")
    expected = json.loads((FIXTURES / f"lab-{profile}.c1.json").read_text(encoding="utf-8"))

    assert isinstance(engine, ScanEngine)
    _assert_c1(result, profile)
    assert _without_scan_id(result) == _without_scan_id(expected)
    assert _without_scan_id(result) == _without_scan_id(
        parse_nmap_xml(FIXTURES / f"lab-{profile}.xml", profile=profile)
    )


def test_fake_engine_ignores_target_and_replays_the_fixture() -> None:
    result = FakeEngine(FIXTURES).run("quick", "10.0.0.0/8")
    assert isinstance(result, ScanResult)
    assert result.subnet == "172.28.0.0/24"
    assert [host.ip for host in result.hosts] == [
        "172.28.0.1",
        "172.28.0.2",
        "172.28.0.3",
        "172.28.0.4",
        "172.28.0.5",
        "172.28.0.6",
        "172.28.0.7",
        "172.28.0.8",
        "172.28.0.9",
        "172.28.0.10",
    ]
    assert all(host.ports == [] for host in result.hosts)


def test_full_fixture_keeps_service_details() -> None:
    result = FakeEngine(FIXTURES).run("full", "172.28.0.0/24")
    assert isinstance(result, ScanResult)
    router = next(host for host in result.hosts if host.ip == "172.28.0.2")
    assert [port.port for port in router.ports] == [53, 80, 5000]
    assert router.ports[0].product == "dnsmasq"


def test_each_request_gets_its_own_scan_id() -> None:
    engine = FakeEngine(FIXTURES)
    first = engine.run("quick", "172.28.0.0/24")
    second = engine.run("quick", "172.28.0.0/24")
    assert isinstance(first, ScanResult)
    assert isinstance(second, ScanResult)
    assert first.scan_id != second.scan_id
    assert _without_scan_id(first) == _without_scan_id(second)


def test_custom_fixture_folder(tmp_path: Path) -> None:
    xml = FIXTURES / "lab-quick.xml"
    (tmp_path / "lab-quick.xml").write_text(xml.read_text(encoding="utf-8"), encoding="utf-8")
    result = FakeEngine(tmp_path).run("quick", "172.28.0.0/24")
    assert isinstance(result, ScanResult)
    assert result.profile == "quick"
    assert result.nmap_version == "7.95"
    assert len(result.hosts) == 10


def test_missing_fixture_folder(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    with pytest.raises(NotADirectoryError, match="Fixture folder"):
        FakeEngine(missing)


def test_missing_profile_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="lab-full.xml"):
        FakeEngine(tmp_path).run("full", "172.28.0.0/24")


def test_bad_xml_goes_through_the_parser(tmp_path: Path) -> None:
    (tmp_path / "lab-quick.xml").write_text("<report/>", encoding="utf-8")
    with pytest.raises(ValueError, match="nmaprun"):
        FakeEngine(tmp_path).run("quick", "172.28.0.0/24")


@pytest.mark.parametrize("profile", ["", "deep", "QUICK"])
def test_fake_engine_rejects_unknown_profile(profile: str) -> None:
    with pytest.raises(ValueError, match="profile"):
        FakeEngine(FIXTURES).run(profile, "172.28.0.0/24")


@pytest.mark.parametrize("target", ["", "   ", "-sS", "172.28.0.0/24 extra"])
def test_fake_engine_rejects_bad_target(target: str) -> None:
    with pytest.raises(ValueError, match="target"):
        FakeEngine(FIXTURES).run("quick", target)


def test_nmap_engine_is_the_same_interface() -> None:
    engine = NmapEngine()
    assert isinstance(engine, ScanEngine)
    assert engine.nmap == "nmap"


@pytest.mark.parametrize(
    ("profile", "timeout_seconds"),
    [("quick", 120), ("full", 1800)],
)
def test_nmap_engine_parses_stdout_xml_without_a_live_scan(
    monkeypatch: pytest.MonkeyPatch, profile: str, timeout_seconds: int
) -> None:
    seen: list[list[str]] = []
    network = "172.28.0.0/24"
    exclude_ip = "172.28.0.6"
    xml = (FIXTURES / f"lab-{profile}.xml").read_text(encoding="utf-8")

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        assert kwargs["capture_output"] is True
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == timeout_seconds
        # XML is stdout from `-oX -`, not a path written beside the command.
        assert argv[argv.index("-oX") + 1] == "-"
        return subprocess.CompletedProcess(argv, 0, stdout=xml, stderr="")

    monkeypatch.setattr(scan_engine.subprocess, "run", fake_run)
    result = NmapEngine(exclude_ip=exclude_ip).run(profile, network)

    assert seen == [build_command(profile, network, exclude_ip)]
    _assert_c1(result, profile)
    assert result.subnet == "172.28.0.0/24"


def test_custom_nmap_binary_keeps_build_command_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []
    network = "172.28.0.0/24"
    exclude_ip = "172.28.0.6"
    xml = (FIXTURES / "lab-quick.xml").read_text(encoding="utf-8")

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout=xml, stderr="")

    monkeypatch.setattr(scan_engine.subprocess, "run", fake_run)
    NmapEngine(nmap="/opt/nmap", exclude_ip=exclude_ip).run("quick", network)

    expected = build_command("quick", network, exclude_ip)
    assert seen == [["/opt/nmap", *expected[1:]]]


def test_nmap_engine_rejects_a_bad_profile_before_scanning(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("nmap must not be started")

    monkeypatch.setattr(scan_engine.subprocess, "run", fail_run)
    with pytest.raises(ValueError, match="profile"):
        NmapEngine().run("deep", "172.28.0.0/24")


@pytest.mark.parametrize("exclude_ip", [None, "", "-sS", "172.28.0.6 extra"])
def test_nmap_engine_rejects_bad_exclude_ip_before_scanning(
    monkeypatch: pytest.MonkeyPatch, exclude_ip: str | None
) -> None:
    def fail_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("nmap must not be started")

    monkeypatch.setattr(scan_engine.subprocess, "run", fail_run)
    with pytest.raises(ValueError, match="exclude_ip"):
        NmapEngine(exclude_ip=exclude_ip).run("quick", "172.28.0.0/24")


@pytest.mark.parametrize(
    ("profile", "timeout_seconds"),
    [("quick", 120), ("full", 1800)],
)
def test_nmap_engine_timeout_fails_the_scan(
    monkeypatch: pytest.MonkeyPatch, profile: str, timeout_seconds: int
) -> None:
    xml = (FIXTURES / f"lab-{profile}.xml").read_text(encoding="utf-8")

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["timeout"] == timeout_seconds
        assert kwargs["shell"] is False
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout_seconds, output=xml)

    monkeypatch.setattr(scan_engine.subprocess, "run", fake_run)
    with pytest.raises(ScanFailed, match="timed out") as caught:
        NmapEngine(exclude_ip="172.28.0.6").run(profile, "172.28.0.0/24")
    assert isinstance(caught.value.__cause__, subprocess.TimeoutExpired)


def test_nmap_engine_nonzero_exit_logs_stderr_and_fails(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    xml = (FIXTURES / "lab-full.xml").read_text(encoding="utf-8")
    stderr = "nmap: simulated failure while scanning"

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 1, stdout=xml, stderr=stderr)

    monkeypatch.setattr(scan_engine.subprocess, "run", fake_run)
    with caplog.at_level(logging.ERROR):
        with pytest.raises(ScanFailed, match="exit code 1"):
            NmapEngine(exclude_ip="172.28.0.6").run("full", "172.28.0.0/24")
    assert stderr in caplog.text
