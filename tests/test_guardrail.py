import logging
from ipaddress import IPv4Address, IPv4Network

import pytest

from watchtower.scanner import guardrail
from watchtower.scanner.guardrail import (
    GuardrailError,
    interface_address_from_ip_json,
    scan_scope,
    scope_from_interface_address,
    validate_target,
)


def _net(text: str) -> IPv4Network:
    return IPv4Network(text)


def test_lab_subnet_is_accepted() -> None:
    network, own_ip = scope_from_interface_address("172.28.0.10/24")
    assert network == _net("172.28.0.0/24")
    assert own_ip == IPv4Address("172.28.0.10")


def test_slash_23_is_the_largest_allowed() -> None:
    network, _ = scope_from_interface_address("192.168.4.5/23")
    assert network.prefixlen == 23


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8/24",  # public
        "10.0.0.5/22",  # too big
        "10.1.2.3/16",  # too big
        "127.0.0.1/8",  # loopback
        "169.254.1.5/24",  # link-local
        "100.64.0.5/24",  # shared address space, not in the allowed ranges
    ],
)
def test_bad_targets_are_refused(address: str) -> None:
    with pytest.raises(GuardrailError):
        scope_from_interface_address(address)


def test_someone_elses_subnet_is_refused() -> None:
    with pytest.raises(GuardrailError, match="does not contain"):
        validate_target(_net("192.168.5.0/24"), IPv4Address("172.28.0.10"))


@pytest.mark.parametrize("address", ["not-an-ip", "", "::1/128", "172.28.0.10/33"])
def test_unparseable_or_ipv6_is_refused(address: str) -> None:
    with pytest.raises(GuardrailError):
        scope_from_interface_address(address)


def test_refusal_is_logged(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING), pytest.raises(GuardrailError):
        scope_from_interface_address("8.8.8.8/24")
    assert "Scan refused" in caplog.text


def test_guardrail_error_is_a_value_error() -> None:
    assert issubclass(GuardrailError, ValueError)


def test_ip_json_is_parsed() -> None:
    sample = (
        '[{"ifname":"eth0","addr_info":'
        '[{"family":"inet","local":"172.28.0.20","prefixlen":24}]}]'
    )
    assert interface_address_from_ip_json(sample, "eth0") == "172.28.0.20/24"


@pytest.mark.parametrize("sample", ["[]", "not json", '[{"addr_info":[]}]'])
def test_missing_address_is_refused(sample: str) -> None:
    with pytest.raises(GuardrailError):
        interface_address_from_ip_json(sample, "eth0")


@pytest.mark.parametrize("name", ["-j", "--help", "eth0; ls", "", "a" * 16, "eth 0", "eth0\n"])
def test_bad_interface_names_never_reach_subprocess(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess.run must not be called for an invalid name")

    monkeypatch.setattr(guardrail.subprocess, "run", fail_if_called)
    with pytest.raises(GuardrailError, match="not a valid interface name"):
        scan_scope(name)


@pytest.mark.parametrize("name", ["eth0", "wlan0", "enp3s0", "br-1a2b3c", "veth.12"])
def test_real_interface_names_pass_the_name_check(name: str) -> None:
    assert guardrail._INTERFACE_NAME.fullmatch(name)
