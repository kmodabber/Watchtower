"""Checks for MAC normalization and private-address labeling."""

from pathlib import Path

import pytest
import yaml

from watchtower.scanner.mac_helpers import (
    PRIVATE_ADDRESS_VENDOR,
    is_randomised,
    label_host_mac,
    normalise,
)
from watchtower.scanner.models import Host


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("3A:7F:21:9C:44:B1", "3a:7f:21:9c:44:b1"),
        ("3a-7f-21-9c-44-b1", "3a:7f:21:9c:44:b1"),
        ("3a7f.219c.44b1", "3a:7f:21:9c:44:b1"),
        ("3a7f219c44b1", "3a:7f:21:9c:44:b1"),
        (" 50:C7:BF:11:00:02 ", "50:c7:bf:11:00:02"),
        (None, None),
    ],
)
def test_normalise(value: str | None, expected: str | None) -> None:
    assert normalise(value) == expected


@pytest.mark.parametrize("value", ["", "abc", "gg:7f:21:9c:44:b1", "aa:bb:cc:dd:ee"])
def test_normalise_rejects_malformed_mac(value: str) -> None:
    with pytest.raises(ValueError, match="Invalid MAC"):
        normalise(value)


@pytest.mark.parametrize(
    ("mac", "expected"),
    [
        ("3a:7f:21:9c:44:b1", True),
        ("a6:5e:90:3d:71:c8", True),
        ("DA:00:00:00:00:01", True),
        ("50:c7:bf:11:00:02", False),
        ("c0:56:e3:12:34:56", False),
        ("00:11:32:33:00:04", False),
        (None, False),
    ],
)
def test_is_randomised(mac: str | None, expected: bool) -> None:
    assert is_randomised(mac) is expected


def test_private_host_gets_vendor_label_and_flag() -> None:
    original = Host(ip="172.28.0.4", mac="3A-7F-21-9C-44-B1", vendor="Unknown")
    labeled = label_host_mac(original)

    assert labeled.mac == "3a:7f:21:9c:44:b1"
    assert labeled.mac_randomised is True
    assert labeled.vendor == PRIVATE_ADDRESS_VENDOR
    assert original.vendor == "Unknown"


def test_normal_host_keeps_its_vendor() -> None:
    labeled = label_host_mac(Host(ip="172.28.0.2", mac="50:C7:BF:11:00:02", vendor="TP-Link"))
    assert labeled.mac_randomised is False
    assert labeled.vendor == "TP-Link"


def test_host_without_mac_is_not_labeled_private() -> None:
    labeled = label_host_mac(Host(ip="172.28.0.1", mac=None, vendor=None))
    assert labeled.mac is None
    assert labeled.mac_randomised is False
    assert labeled.vendor is None


def test_every_lab_device_mac_matches_expected_privacy_label() -> None:
    inventory_path = Path(__file__).resolve().parents[1] / "lab" / "inventory.yaml"
    inventory = yaml.safe_load(inventory_path.read_text(encoding="utf-8"))
    devices = inventory["devices"]
    assert devices, "Lab inventory should contain devices"

    for device in devices:
        expected_private = device["name"] in {"laptop", "phone"}
        host = Host(ip="192.168.1.2", mac=device["mac"], vendor="Known vendor")
        labeled = label_host_mac(host)
        assert labeled.mac_randomised is expected_private, device["name"]
        if expected_private:
            assert labeled.vendor == PRIVATE_ADDRESS_VENDOR
        else:
            assert labeled.vendor == "Known vendor"
