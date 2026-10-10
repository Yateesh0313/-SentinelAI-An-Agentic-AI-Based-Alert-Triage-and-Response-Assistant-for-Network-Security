"""SentinelAI — Cross-platform network interface detection.

Detects active network interfaces for Suricata live capture.
Uses psutil for portable enumeration across Windows/Linux/macOS.

SCOPE LIMIT:
    IP-based network traffic only (WiFi / Ethernet / hotspot).
    Bluetooth interfaces are explicitly EXCLUDED — Suricata does not
    support Bluetooth traffic monitoring.
"""

from __future__ import annotations

import platform
import re
import socket
from typing import Any

try:
    import psutil

    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


# ---------------------------------------------------------------------------
# Bluetooth interface name patterns (to exclude)
# ---------------------------------------------------------------------------

_BLUETOOTH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"bluetooth", re.IGNORECASE),
    re.compile(r"^bt[-_\d]", re.IGNORECASE),
    re.compile(r"bnep\d*", re.IGNORECASE),
    re.compile(r"pan\d*", re.IGNORECASE),
]


def _is_bluetooth(name: str) -> bool:
    """Check if an interface name looks like a Bluetooth adapter."""
    return any(pat.search(name) for pat in _BLUETOOTH_PATTERNS)


# ---------------------------------------------------------------------------
# Interface type heuristics
# ---------------------------------------------------------------------------

_WIFI_PATTERNS = [
    re.compile(r"wi[-\s]?fi", re.IGNORECASE),
    re.compile(r"wlan\d*", re.IGNORECASE),
    re.compile(r"wireless", re.IGNORECASE),
    re.compile(r"wlp\d+", re.IGNORECASE),    # Linux: wlp2s0
    re.compile(r"ath\d+", re.IGNORECASE),
]

_ETHERNET_PATTERNS = [
    re.compile(r"ethernet", re.IGNORECASE),
    re.compile(r"^eth\d*$", re.IGNORECASE),
    re.compile(r"^en[ops]\d+", re.IGNORECASE),  # Linux: ens33, enp0s3
    re.compile(r"^em\d+", re.IGNORECASE),
]

_LOOPBACK_PATTERNS = [
    re.compile(r"loopback", re.IGNORECASE),
    re.compile(r"^lo$", re.IGNORECASE),
]

_VIRTUAL_PATTERNS = [
    re.compile(r"docker", re.IGNORECASE),
    re.compile(r"veth", re.IGNORECASE),
    re.compile(r"virbr", re.IGNORECASE),
    re.compile(r"vmnet", re.IGNORECASE),
    re.compile(r"vbox", re.IGNORECASE),
    re.compile(r"hyper-v", re.IGNORECASE),
    re.compile(r"wsl", re.IGNORECASE),
]


def _classify_interface(name: str) -> str:
    """Classify an interface as wifi, ethernet, loopback, virtual, or other."""
    if any(p.search(name) for p in _LOOPBACK_PATTERNS):
        return "loopback"
    if _is_bluetooth(name):
        return "bluetooth"
    if any(p.search(name) for p in _VIRTUAL_PATTERNS):
        return "virtual"
    if any(p.search(name) for p in _WIFI_PATTERNS):
        return "wifi"
    if any(p.search(name) for p in _ETHERNET_PATTERNS):
        return "ethernet"
    return "other"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_interfaces(
    include_loopback: bool = False,
    include_down: bool = False,
    include_virtual: bool = False,
) -> list[dict[str, Any]]:
    """Detect available network interfaces.

    Returns a list of dicts, each with:
        name      : str  — interface name (e.g. "Wi-Fi", "eth0")
        ip        : str  — IPv4 address (or "" if none)
        type      : str  — "wifi", "ethernet", "loopback", "virtual", "other"
        active    : bool — True if the interface is up and has a link
        is_default: bool — True if this looks like the best capture target

    Bluetooth interfaces are always excluded.
    """
    if not _HAS_PSUTIL:
        return _fallback_detect()

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    interfaces: list[dict[str, Any]] = []

    for iface_name, addr_list in addrs.items():
        # Always exclude Bluetooth
        if _is_bluetooth(iface_name):
            continue

        iface_type = _classify_interface(iface_name)

        # Filter by type
        if iface_type == "loopback" and not include_loopback:
            continue
        if iface_type == "virtual" and not include_virtual:
            continue

        # Check if interface is up
        iface_stats = stats.get(iface_name)
        is_up = iface_stats.isup if iface_stats else False

        if not is_up and not include_down:
            continue

        # Get IPv4 address
        ipv4 = ""
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ipv4 = addr.address
                break

        interfaces.append({
            "name": iface_name,
            "ip": ipv4,
            "type": iface_type,
            "active": is_up and bool(ipv4),
            "is_default": False,  # Set below
        })

    # Mark the best default: prefer active wifi > active ethernet > other active
    _mark_default(interfaces)

    return interfaces


def _mark_default(interfaces: list[dict[str, Any]]) -> None:
    """Mark the best default interface for Suricata capture."""
    priority = {"wifi": 0, "ethernet": 1, "other": 2, "virtual": 3, "loopback": 4}

    active = [i for i in interfaces if i["active"]]
    if not active:
        return

    active.sort(key=lambda i: priority.get(i["type"], 99))
    active[0]["is_default"] = True


def get_default_interface() -> dict[str, Any] | None:
    """Return the best default interface for Suricata capture, or None."""
    interfaces = detect_interfaces()
    for iface in interfaces:
        if iface["is_default"]:
            return iface
    # Fall back to first active
    active = [i for i in interfaces if i["active"]]
    return active[0] if active else None


def _fallback_detect() -> list[dict[str, Any]]:
    """Fallback interface detection without psutil.

    Uses socket to get the machine's primary IP and returns a single
    synthetic interface entry.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"

    os_name = platform.system().lower()
    iface_name = "Wi-Fi" if os_name == "windows" else "wlan0"

    return [{
        "name": iface_name,
        "ip": ip,
        "type": "wifi" if ip != "127.0.0.1" else "loopback",
        "active": ip != "127.0.0.1",
        "is_default": True,
    }]
