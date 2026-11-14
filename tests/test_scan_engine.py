"""WT-FR-13: FakeEngine returns saved WT-55 scans in the C1 shape.

NmapEngine is only checked where a stand-in subprocess writes XML. Nothing
here starts Nmap or touches the network. The lab test (WT-54) covers the
real binary.
"""

import json
import subprocess
import uuid
from pathlib import Path

import pytest

from watchtower.scanner import scan_engine
from watchtower.scanner.nmap_parser import parse_nmap_xml
from watchtower.scanner.scan_engine import FakeEngine, NmapEngine, ScanEngine

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


def _without_scan_id(result: dict) -> dict:
    # scan_id is a fresh UUID on every parse, so it can't be compared.
    return {key: value for key, value in result.items() if key != "scan_id"}


def _assert_c1(result: dict, profile: str) -> None:
    assert set(result) == C1_KEYS
    assert result["profile"] == profile
    uuid.UUID(result["scan_id"])
    assert uuid.UUID(result["scan_id"]).version == 4
    assert result["hosts"]
    for host in result["hosts"]:
        assert set(host) == HOST_KEYS
        for port in host["ports"]:
            assert set(port) == PORT_KEYS


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
    assert result["subnet"] == "172.28.0.0/24"
    assert [host["ip"] for host in result["hosts"]] == [
        "172.28.0.1",
        "172.28.0.2",
        "172.28.0.3",
        "172.28.0.4",
        "172.28.0.5",
    ]
    assert all(host["ports"] == [] for host in result["hosts"])


def test_full_fixture_keeps_service_details() -> None:
    result = FakeEngine(FIXTURES).run("full", "172.28.0.0/24")
    router = next(host for host in result["hosts"] if host["ip"] == "172.28.0.2")
    assert [port["port"] for port in router["ports"]] == [53, 80, 5000]
    assert router["ports"][0]["product"] == "dnsmasq"


def test_each_request_gets_its_own_scan_id() -> None:
    engine = FakeEngine(FIXTURES)
    first = engine.run("quick", "172.28.0.0/24")
    second = engine.run("quick", "172.28.0.0/24")
    assert first["scan_id"] != second["scan_id"]
    assert _without_scan_id(first) == _without_scan_id(second)


def test_custom_fixture_folder(tmp_path: Path) -> None:
    xml = FIXTURES / "lab-quick.xml"
    (tmp_path / "lab-quick.xml").write_text(xml.read_text(encoding="utf-8"), encoding="utf-8")
    result = FakeEngine(tmp_path).run("quick", "172.28.0.0/24")
    assert result["profile"] == "quick"
    assert result["nmap_version"] == "7.95"
    assert len(result["hosts"]) == 5


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
    ("profile", "flag"),
    [("quick", "-sn"), ("full", "-sV")],
)
def test_nmap_engine_parses_subprocess_xml_without_a_live_scan(
    monkeypatch: pytest.MonkeyPatch, profile: str, flag: str
) -> None:
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(argv)
        assert kwargs["check"] is True
        assert kwargs["timeout"] == 900
        xml_path = Path(argv[argv.index("-oX") + 1])
        xml_path.write_text(
            (FIXTURES / "lab-quick.xml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(scan_engine.subprocess, "run", fake_run)
    result = NmapEngine().run(profile, "172.28.0.0/24")

    assert len(seen) == 1
    assert seen[0][0] == "nmap"
    assert flag in seen[0]
    assert seen[0][-1] == "172.28.0.0/24"
    assert "-oX" in seen[0]
    _assert_c1(result, profile)
    assert result["subnet"] == "172.28.0.0/24"


def test_nmap_engine_rejects_a_bad_profile_before_scanning(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("nmap must not be started")

    monkeypatch.setattr(scan_engine.subprocess, "run", fail_run)
    with pytest.raises(ValueError, match="profile"):
        NmapEngine().run("deep", "172.28.0.0/24")
