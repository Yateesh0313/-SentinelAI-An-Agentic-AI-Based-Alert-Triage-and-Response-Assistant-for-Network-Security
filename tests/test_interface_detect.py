"""Tests for Cross-Platform Interface Detection (Phase 24 Suricata Live Capture)."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "backend"))

from interface_detect import (
    _is_bluetooth,
    _classify_interface,
    detect_interfaces,
    get_default_interface,
    _fallback_detect,
)


def test_is_bluetooth():
    """Verify Bluetooth interface names are correctly identified and rejected."""
    bluetooth_names = [
        "Bluetooth Device (Personal Area Network)",
        "Bluetooth Network Connection",
        "bt-pan",
        "bt0",
        "bnep0",
        "bnep1",
        "pan0",
    ]
    for name in bluetooth_names:
        assert _is_bluetooth(name), f"Expected {name} to be flagged as Bluetooth"

    non_bluetooth_names = [
        "Wi-Fi",
        "wlan0",
        "wlp2s0",
        "Ethernet",
        "eth0",
        "ens33",
        "lo",
    ]
    for name in non_bluetooth_names:
        assert not _is_bluetooth(name), f"Expected {name} NOT to be flagged as Bluetooth"


def test_classify_interface():
    """Verify interface naming patterns map to correct categories."""
    assert _classify_interface("Wi-Fi") == "wifi"
    assert _classify_interface("wlan0") == "wifi"
    assert _classify_interface("wlp2s0") == "wifi"
    assert _classify_interface("Ethernet") == "ethernet"
    assert _classify_interface("eth0") == "ethernet"
    assert _classify_interface("ens33") == "ethernet"
    assert _classify_interface("lo") == "loopback"
    assert _classify_interface("Loopback Pseudo-Interface 1") == "loopback"
    assert _classify_interface("docker0") == "virtual"
    assert _classify_interface("veth1234") == "virtual"
    assert _classify_interface("vboxnet0") == "virtual"
    assert _classify_interface("Bluetooth Device") == "bluetooth"


def test_detect_interfaces():
    """Verify detect_interfaces returns valid list of interface dictionaries."""
    ifaces = detect_interfaces()
    assert isinstance(ifaces, list)

    for iface in ifaces:
        assert "name" in iface
        assert "ip" in iface
        assert "type" in iface
        assert "active" in iface
        assert "is_default" in iface
        # Ensure no bluetooth leaked through
        assert not _is_bluetooth(iface["name"])
        assert iface["type"] != "bluetooth"


def test_get_default_interface():
    """Verify get_default_interface returns either an interface dict or None."""
    default = get_default_interface()
    if default is not None:
        assert isinstance(default, dict)
        assert "name" in default
        assert not _is_bluetooth(default["name"])


def test_fallback_detect():
    """Verify fallback detection functions without psutil."""
    fallback_ifaces = _fallback_detect()
    assert len(fallback_ifaces) >= 1
    fb = fallback_ifaces[0]
    assert "name" in fb
    assert "ip" in fb
    assert "type" in fb
    assert fb["is_default"] is True
    assert not _is_bluetooth(fb["name"])
