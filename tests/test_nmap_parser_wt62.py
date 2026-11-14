"""WT-62 (WT-FR-11, TC-03): the parser returns C1 for real Nmap output and raises
ScanParseError, with a clear message, for anything else."""

from pathlib import Path

import pytest

from watchtower.scanner.models import ScanResult
from watchtower.scanner.nmap_parser import ScanParseError, parse_nmap_xml

FIXTURES = Path(__file__).resolve().parent / "fixtures"

HEADER = '<nmaprun args="nmap -sS -sV 172.28.0.0/24" start="1762416509" version="7.95">'
FOOTER = '<runstats><finished time="1762416586"/></runstats></nmaprun>'


def _xml(tmp_path: Path, body: str, header: str = HEADER, footer: str = FOOTER) -> Path:
    path = tmp_path / "scan.xml"
    path.write_text(f'<?xml version="1.0"?>{header}{body}{footer}', encoding="utf-8")
    return path


def _host(ports: str = "", status: str = "up", mac: str = "") -> str:
    return (
        f'<host><status state="{status}"/><address addr="172.28.0.9" addrtype="ipv4"/>'
        f"{mac}<ports>{ports}</ports></host>"
    )


@pytest.mark.parametrize("profile", ["quick", "full"])
def test_saved_lab_scans_fit_c1(profile: str) -> None:
    result = ScanResult.from_dict(parse_nmap_xml(FIXTURES / f"lab-{profile}.xml"))
    assert result.profile == profile
    assert result.hosts


def test_scan_parse_error_is_a_value_error() -> None:
    # Callers (FakeEngine, lab/discover_c1.py) already catch ValueError.
    assert issubclass(ScanParseError, ValueError)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "Malformed XML"),
        ("<nmaprun", "Malformed XML"),
        ("<report/>", "nmaprun"),
        ('<nmaprun args="-sn 172.28.0.0/24" start="1">' + FOOTER, "version"),
        ('<nmaprun args="-sn 172.28.0.0/24" version="7.95">' + FOOTER, "start"),
        ('<nmaprun args="-sn 172.28.0.0/24" start="1" version="7.95"></nmaprun>', "finished"),
    ],
)
def test_broken_input_raises_scan_parse_error(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "scan.xml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ScanParseError, match=message):
        parse_nmap_xml(path)


def test_bad_start_time(tmp_path: Path) -> None:
    header = HEADER.replace('start="1762416509"', 'start="soon"')
    with pytest.raises(ScanParseError, match="start"):
        parse_nmap_xml(_xml(tmp_path, "", header=header))


def test_no_subnet_in_args(tmp_path: Path) -> None:
    header = HEADER.replace(" 172.28.0.0/24", "")
    with pytest.raises(ScanParseError, match="subnet"):
        parse_nmap_xml(_xml(tmp_path, "", header=header))


def test_host_without_ip(tmp_path: Path) -> None:
    body = '<host><status state="up"/><address addr="aa:bb:cc:dd:ee:ff" addrtype="mac"/></host>'
    with pytest.raises(ScanParseError, match="IPv4"):
        parse_nmap_xml(_xml(tmp_path, body))


def test_port_without_number(tmp_path: Path) -> None:
    body = _host('<port protocol="tcp"><state state="open"/></port>')
    with pytest.raises(ScanParseError, match="portid"):
        parse_nmap_xml(_xml(tmp_path, body))


def test_missing_file_is_still_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        parse_nmap_xml(tmp_path / "nope.xml")


def test_only_hosts_that_are_up(tmp_path: Path) -> None:
    result = parse_nmap_xml(_xml(tmp_path, _host(status="up") + _host(status="down")))
    assert len(result["hosts"]) == 1


def test_only_open_ports(tmp_path: Path) -> None:
    ports = "".join(
        f'<port protocol="tcp" portid="{n}"><state state="{state}"/></port>'
        for n, state in [(22, "open"), (23, "closed"), (80, "filtered"), (161, "open|filtered")]
    )
    result = parse_nmap_xml(_xml(tmp_path, _host(ports)))
    assert [p["port"] for p in result["hosts"][0]["ports"]] == [22]


def test_host_without_mac_is_fine(tmp_path: Path) -> None:
    # Nmap can't see the MAC of the machine it runs on.
    host = parse_nmap_xml(_xml(tmp_path, _host()))["hosts"][0]
    assert host["mac"] is None and host["vendor"] is None and host["mac_randomised"] is False


def test_quick_scan_without_ports_element(tmp_path: Path) -> None:
    header = HEADER.replace("-sS -sV", "-sn")
    body = '<host><status state="up"/><address addr="172.28.0.9" addrtype="ipv4"/></host>'
    result = parse_nmap_xml(_xml(tmp_path, body, header=header))
    assert result["profile"] == "quick"
    assert result["hosts"][0]["ports"] == []


def test_service_name_without_product(tmp_path: Path) -> None:
    # Version detection failed: Nmap still guesses the name from the port number.
    port = '<port protocol="tcp" portid="554"><state state="open"/><service name="rtsp"/></port>'
    p = parse_nmap_xml(_xml(tmp_path, _host(port)))["hosts"][0]["ports"][0]
    assert (p["service"], p["product"], p["version"]) == ("rtsp", None, None)
