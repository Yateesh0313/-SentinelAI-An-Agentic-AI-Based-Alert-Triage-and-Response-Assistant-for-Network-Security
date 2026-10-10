"""SentinelAI — Live Network Traffic Monitor (Phase 23).

Real-time packet capture from actual WiFi / Ethernet interfaces using Scapy.
Captures live traffic on the machine's network interface, extracts
NSL-KDD-compatible connection features, runs XGBoost ML detection, and
feeds anomalies through the full agentic triage pipeline.

ARCHITECTURE:
    WiFi/Eth Interface → Scapy sniff (async) → ConnectionTracker
      → NSL-KDD feature extraction → XGBoost detection
      → Anomaly? → LangGraph agent triage → Risk scoring → Dashboard

MODES:
    - interface="Wi-Fi"       → capture from WiFi adapter
    - interface="Ethernet"    → capture from Ethernet adapter
    - interface=<GUID>        → capture from specific interface by GUID

SAFETY:
    - Only captures from interfaces on THIS machine
    - Configurable packet/time limits
    - Graceful start/stop with async support
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Awaitable

from scapy.all import (
    IP, TCP, UDP, ICMP, DNS, Raw,
    sniff, get_if_list, conf,
)


# ---------------------------------------------------------------------------
# Windows interface resolver
# ---------------------------------------------------------------------------

def get_available_interfaces() -> list[dict[str, Any]]:
    """Discover available network interfaces with details.

    Returns a list of dicts with keys:
        name, description, guid, mac, ips, is_up, type
    """
    interfaces = []

    try:
        import scapy.arch.windows as win
        raw_ifaces = win.get_windows_if_list()

        # Also get IP info from ipconfig
        import subprocess
        ipconfig = subprocess.run(
            ["ipconfig"], capture_output=True, text=True
        ).stdout

        for iface in raw_ifaces:
            name = iface.get("name", "")
            desc = iface.get("description", "")
            guid = iface.get("guid", "")
            mac = iface.get("mac", "")
            ips = iface.get("ips", [])
            itype = iface.get("type", 0)

            # Filter: only real adapters (type 6=ethernet, 71=wifi)
            # and skip sub-layer filters
            if itype not in (6, 71):
                continue
            # Skip WAN Miniport, filter drivers, QoS, etc.
            skip_keywords = [
                "WAN Miniport", "Filter Driver", "QoS Packet",
                "WFP", "LightWeight", "Virtual WiFi",
            ]
            if any(kw in desc for kw in skip_keywords):
                continue

            # Try to find IP from ipconfig output
            ip_addr = None
            if ips:
                for ip in ips:
                    if "." in ip and not ip.startswith("169.254"):
                        ip_addr = ip
                        break

            is_up = ip_addr is not None

            interfaces.append({
                "name": name,
                "description": desc,
                "guid": guid,
                "mac": mac,
                "ip": ip_addr,
                "is_up": is_up,
                "type": "wifi" if itype == 71 else "ethernet",
            })

    except Exception as e:
        # Fallback: use raw Scapy interface list
        for iface_name in get_if_list():
            interfaces.append({
                "name": iface_name,
                "description": iface_name,
                "guid": iface_name,
                "mac": "",
                "ip": None,
                "is_up": True,
                "type": "unknown",
            })

    return interfaces


def resolve_interface(name_or_guid: str) -> str | None:
    """Resolve a friendly name like 'Wi-Fi' or 'Ethernet' to a Scapy GUID.

    Also accepts raw GUIDs directly.
    """
    if name_or_guid.startswith("{"):
        return name_or_guid  # Already a GUID

    try:
        import scapy.arch.windows as win
        raw_ifaces = win.get_windows_if_list()
        for iface in raw_ifaces:
            iface_name = iface.get("name", "")
            if iface_name.lower() == name_or_guid.lower():
                return iface.get("guid", None)
            # Partial match
            if name_or_guid.lower() in iface_name.lower():
                return iface.get("guid", None)
    except Exception:
        pass

    return name_or_guid  # Return as-is on non-Windows


# ---------------------------------------------------------------------------
# Connection tracker (enhanced from scapy_capture.py)
# ---------------------------------------------------------------------------

class LiveConnectionTracker:
    """Track connections in real-time from live packet capture.

    Groups packets by 5-tuple and produces NSL-KDD-style feature dicts
    when connections close or when a timeout expires.
    """

    CONNECTION_TIMEOUT = 30.0  # seconds before an idle connection is flushed

    def __init__(self):
        self._connections: dict[str, dict[str, Any]] = {}
        self._completed: list[dict[str, Any]] = []
        self._packet_count = 0
        self._connection_count = 0

        # Sliding window stats for NSL-KDD "count" and "srv_count" features
        self._recent_connections: list[dict[str, Any]] = []
        self._WINDOW_SIZE = 100  # last N connections for stat calculation

    @property
    def stats(self) -> dict[str, int]:
        return {
            "packets_processed": self._packet_count,
            "active_connections": len(self._connections),
            "completed_connections": self._connection_count,
        }

    @staticmethod
    def _conn_key(pkt) -> str | None:
        """Build a connection key from a packet."""
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        if pkt.haslayer(TCP):
            proto = "tcp"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "udp"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "icmp"
            sport = 0
            dport = 0
        else:
            return None
        return f"{ip.src}:{sport}->{ip.dst}:{dport}/{proto}"

    def process_packet(self, pkt) -> dict[str, Any] | None:
        """Process a packet, return a completed event if connection closes."""
        key = self._conn_key(pkt)
        if key is None:
            return None

        self._packet_count += 1
        ip = pkt[IP]
        now = time.time()

        if key not in self._connections:
            proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "icmp"
            self._connections[key] = {
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "src_port": pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0),
                "dst_port": pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0),
                "proto": proto,
                "start_time": now,
                "last_time": now,
                "src_bytes": 0,
                "dst_bytes": 0,
                "src_packets": 0,
                "dst_packets": 0,
                "flags_seen": set(),
                "service": self._guess_service(pkt),
                "has_payload": False,
                "urgent_count": 0,
                "wrong_fragments": 0,
            }

        conn = self._connections[key]
        conn["last_time"] = now
        payload_len = len(pkt[IP].payload) if pkt.haslayer(IP) else 0

        # Determine direction
        if ip.src == conn["src_ip"]:
            conn["src_bytes"] += payload_len
            conn["src_packets"] += 1
        else:
            conn["dst_bytes"] += payload_len
            conn["dst_packets"] += 1

        # Check for payload content
        if pkt.haslayer(Raw) and len(pkt[Raw].load) > 0:
            conn["has_payload"] = True

        # Track TCP flags
        if pkt.haslayer(TCP):
            flags = str(pkt[TCP].flags)
            conn["flags_seen"].add(flags)

            # Track urgent packets
            if "U" in flags:
                conn["urgent_count"] += 1

            # Check for connection completion (FIN or RST)
            if "F" in flags or "R" in flags:
                return self._complete_connection(key)

        return None

    def flush_timed_out(self) -> list[dict[str, Any]]:
        """Flush connections that have been idle too long."""
        now = time.time()
        timed_out = []
        for key in list(self._connections.keys()):
            conn = self._connections[key]
            if now - conn["last_time"] > self.CONNECTION_TIMEOUT:
                event = self._complete_connection(key)
                if event:
                    timed_out.append(event)
        return timed_out

    def flush_all(self) -> list[dict[str, Any]]:
        """Force-complete all active connections."""
        events = []
        for key in list(self._connections.keys()):
            event = self._complete_connection(key)
            if event:
                events.append(event)
        return events

    def _complete_connection(self, key: str) -> dict[str, Any] | None:
        """Move connection from active to completed and return NSL-KDD event."""
        if key not in self._connections:
            return None

        conn = self._connections.pop(key)
        self._connection_count += 1

        event = self._conn_to_nsl_event(conn)

        # Update sliding window for stats
        self._recent_connections.append({
            "service": conn["service"],
            "dst_ip": conn["dst_ip"],
            "dst_port": conn["dst_port"],
            "flag": event.get("flag", "OTH"),
            "time": conn["last_time"],
        })
        if len(self._recent_connections) > self._WINDOW_SIZE:
            self._recent_connections.pop(0)

        # Calculate sliding window stats
        self._enrich_window_stats(event, conn)

        return event

    def _enrich_window_stats(self, event: dict, conn: dict) -> None:
        """Enrich event with sliding-window stats like NSL-KDD count/srv_count."""
        recent = self._recent_connections
        if not recent:
            return

        dst_ip = conn["dst_ip"]
        service = conn["service"]

        # count: connections to same dst in last window
        same_dst = [c for c in recent if c["dst_ip"] == dst_ip]
        event["count"] = len(same_dst)

        # srv_count: connections with same service in last window
        same_srv = [c for c in recent if c["service"] == service]
        event["srv_count"] = len(same_srv)

        n = len(same_dst) or 1
        # serror_rate
        syn_errors = [c for c in same_dst if c["flag"] in ("S0", "REJ")]
        event["serror_rate"] = round(len(syn_errors) / n, 4)
        event["srv_serror_rate"] = event["serror_rate"]

        # rerror_rate
        rej_errors = [c for c in same_dst if c["flag"] == "REJ"]
        event["rerror_rate"] = round(len(rej_errors) / n, 4)
        event["srv_rerror_rate"] = event["rerror_rate"]

        # same_srv_rate
        same_srv_same_dst = [c for c in same_dst if c["service"] == service]
        event["same_srv_rate"] = round(len(same_srv_same_dst) / n, 4)
        event["diff_srv_rate"] = round(1.0 - event["same_srv_rate"], 4)

        # dst_host stats
        event["dst_host_count"] = min(event["count"], 255)
        event["dst_host_srv_count"] = min(len(same_srv_same_dst), 255)
        event["dst_host_same_srv_rate"] = event["same_srv_rate"]
        event["dst_host_diff_srv_rate"] = event["diff_srv_rate"]
        event["dst_host_serror_rate"] = event["serror_rate"]
        event["dst_host_srv_serror_rate"] = event["srv_serror_rate"]
        event["dst_host_rerror_rate"] = event["rerror_rate"]
        event["dst_host_srv_rerror_rate"] = event["srv_rerror_rate"]

    def _guess_service(self, pkt) -> str:
        """Map destination port to NSL-KDD service name."""
        port = 0
        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            port = pkt[UDP].dport

        service_map = {
            80: "http", 443: "http", 8080: "http", 8443: "http",
            21: "ftp", 20: "ftp_data",
            22: "ssh", 23: "telnet",
            25: "smtp", 587: "smtp",
            53: "domain_u", 110: "pop_3",
            143: "imap4", 993: "imap4",
            123: "ntp_u", 161: "other",
            3389: "other", 445: "other",
            3306: "other", 5432: "other",
            6379: "other", 27017: "other",
        }
        return service_map.get(port, "other")

    def _derive_flag(self, conn: dict) -> str:
        """Derive NSL-KDD flag from TCP flags seen."""
        flags = conn["flags_seen"]
        if conn["proto"] != "tcp":
            return "SF"

        flags_str = " ".join(flags)
        if "S" in flags_str and "A" not in flags_str and "F" not in flags_str:
            return "S0"
        if "R" in flags_str:
            if "S" in flags_str and "A" in flags_str:
                return "RSTO"
            return "REJ"
        if "F" in flags_str and "A" in flags_str:
            return "SF"
        if "S" in flags_str and "A" in flags_str:
            return "S1"
        return "OTH"

    def _conn_to_nsl_event(self, conn: dict) -> dict[str, Any]:
        """Convert a connection record to NSL-KDD feature dict."""
        duration = conn["last_time"] - conn["start_time"]
        flag = self._derive_flag(conn)

        event: dict[str, Any] = {
            # Mapped features
            "duration": round(duration, 2),
            "protocol_type": conn["proto"],
            "service": conn["service"],
            "flag": flag,
            "src_bytes": conn["src_bytes"],
            "dst_bytes": conn["dst_bytes"],
            "land": 1 if (conn["src_ip"] == conn["dst_ip"] and conn["src_port"] == conn["dst_port"]) else 0,
            "logged_in": 1 if (conn["service"] in ("ssh", "telnet", "ftp") and flag == "SF") else 0,
            "wrong_fragment": conn["wrong_fragments"],
            "urgent": conn["urgent_count"],

            # Content features
            "hot": 0,
            "num_failed_logins": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,

            # Connection-level stats (enriched by _enrich_window_stats)
            "count": 0, "srv_count": 0,
            "serror_rate": 0.0, "srv_serror_rate": 0.0,
            "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
            "same_srv_rate": 0.0, "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,

            # Host-level stats
            "dst_host_count": 0, "dst_host_srv_count": 0,
            "dst_host_same_srv_rate": 0.0, "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 0.0,
            "dst_host_srv_diff_host_rate": 0.0,
            "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
            "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
        }

        # Metadata (not part of the 41 ML features)
        event["_meta"] = {
            "source": "live_capture",
            "src_ip": conn["src_ip"],
            "src_port": conn["src_port"],
            "dst_ip": conn["dst_ip"],
            "dst_port": conn["dst_port"],
            "packets": conn["src_packets"] + conn["dst_packets"],
            "capture_time": time.time(),
        }

        return event


# ---------------------------------------------------------------------------
# Live Network Monitor (async)
# ---------------------------------------------------------------------------

class LiveNetworkMonitor:
    """Async live network traffic monitor.

    Captures packets from a real network interface, extracts connection
    features, and invokes a callback for each completed connection event.

    Parameters
    ----------
    interface : str
        Interface name (e.g. 'Wi-Fi', 'Ethernet') or GUID.
    on_event : callable
        Async callback invoked with each NSL-KDD event dict.
    packet_limit : int
        Max packets before auto-stop (0 = unlimited).
    time_limit : int
        Max seconds before auto-stop (0 = unlimited).
    bpf_filter : str
        Berkeley Packet Filter expression (default: 'ip' for all IP traffic).
    """

    def __init__(
        self,
        interface: str = "Wi-Fi",
        on_event: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
        packet_limit: int = 0,
        time_limit: int = 0,
        bpf_filter: str = "ip",
    ):
        self.interface_name = interface
        self.on_event = on_event
        self.packet_limit = packet_limit
        self.time_limit = time_limit
        self.bpf_filter = bpf_filter

        self._resolved_iface: str | None = None
        self._tracker = LiveConnectionTracker()
        self._running = False
        self._capture_task: asyncio.Task | None = None
        self._flush_task: asyncio.Task | None = None
        self._start_time: float = 0
        self._event_count = 0
        self._anomaly_count = 0

    @property
    def running(self) -> bool:
        return self._running

    @property
    def stats(self) -> dict[str, Any]:
        uptime = time.time() - self._start_time if self._running else 0
        return {
            "running": self._running,
            "interface": self.interface_name,
            "uptime_seconds": round(uptime, 1),
            "events_processed": self._event_count,
            "anomalies_detected": self._anomaly_count,
            **self._tracker.stats,
        }

    async def start(self) -> dict[str, Any]:
        """Start live packet capture on the configured interface."""
        if self._running:
            return {"status": "already_running", **self.stats}

        # Resolve interface name to GUID
        self._resolved_iface = resolve_interface(self.interface_name)
        if not self._resolved_iface:
            return {"status": "error", "detail": f"Could not resolve interface: {self.interface_name}"}

        self._running = True
        self._start_time = time.time()
        self._event_count = 0
        self._anomaly_count = 0
        self._tracker = LiveConnectionTracker()

        # Start capture in a thread (Scapy sniff is blocking)
        self._capture_task = asyncio.create_task(self._capture_loop())

        # Start periodic flush for timed-out connections
        self._flush_task = asyncio.create_task(self._flush_loop())

        print(f"  [live-monitor] Started on interface '{self.interface_name}' "
              f"(resolved: {self._resolved_iface})")
        return {"status": "started", **self.stats}

    async def stop(self) -> dict[str, Any]:
        """Stop live packet capture."""
        if not self._running:
            return {"status": "not_running"}

        self._running = False

        # Cancel tasks
        for task in [self._capture_task, self._flush_task]:
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Flush remaining connections
        remaining = self._tracker.flush_all()
        for event in remaining:
            await self._dispatch_event(event)

        stats = self.stats
        print(f"  [live-monitor] Stopped. {stats}")
        return {"status": "stopped", **stats}

    async def _capture_loop(self) -> None:
        """Main capture loop — runs Scapy sniff in a thread."""
        loop = asyncio.get_event_loop()

        def _sniff_callback(pkt):
            """Called by Scapy for each captured packet."""
            if not self._running:
                return

            completed_event = self._tracker.process_packet(pkt)
            if completed_event:
                # Schedule async dispatch from the sync callback
                loop.call_soon_threadsafe(
                    asyncio.ensure_future,
                    self._dispatch_event(completed_event),
                )

        def _run_sniff():
            """Run blocking Scapy sniff."""
            try:
                sniff_kwargs = {
                    "iface": self._resolved_iface,
                    "prn": _sniff_callback,
                    "store": False,
                    "filter": self.bpf_filter,
                    "stop_filter": lambda _: not self._running,
                }
                if self.packet_limit > 0:
                    sniff_kwargs["count"] = self.packet_limit
                if self.time_limit > 0:
                    sniff_kwargs["timeout"] = self.time_limit

                sniff(**sniff_kwargs)
            except Exception as exc:
                print(f"  [live-monitor] Capture error: {exc}")
            finally:
                self._running = False

        try:
            await loop.run_in_executor(None, _run_sniff)
        except asyncio.CancelledError:
            pass

    async def _flush_loop(self) -> None:
        """Periodically flush timed-out connections."""
        try:
            while self._running:
                await asyncio.sleep(5.0)
                timed_out = self._tracker.flush_timed_out()
                for event in timed_out:
                    await self._dispatch_event(event)
        except asyncio.CancelledError:
            pass

    async def _dispatch_event(self, event: dict[str, Any]) -> None:
        """Dispatch a completed connection event to the callback."""
        self._event_count += 1
        event["event_index"] = self._event_count
        event["source"] = "live_capture"

        meta = event.get("_meta", {})
        src = meta.get("src_ip", "?")
        dst = meta.get("dst_ip", "?")
        dst_port = meta.get("dst_port", 0)
        service = event.get("service", "?")

        if self._event_count % 10 == 1 or self._event_count <= 5:
            print(f"  [live-monitor] #{self._event_count} "
                  f"{src} -> {dst}:{dst_port} ({service}) "
                  f"bytes={event.get('src_bytes', 0)}+{event.get('dst_bytes', 0)}")

        if self.on_event:
            try:
                await self.on_event(event)
            except Exception as exc:
                print(f"  [live-monitor] Event callback error: {exc}")
