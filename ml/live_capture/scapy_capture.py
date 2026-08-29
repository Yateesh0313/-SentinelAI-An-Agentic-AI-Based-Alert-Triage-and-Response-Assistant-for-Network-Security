"""SentinelAI — Scapy Live Packet Capture (Phase 14 — Windows fallback).

Captures live network packets from the local interface using Scapy,
extracts connection-level features, and maps them to NSL-KDD-style
events for the ML detection pipeline.

SCOPE LIMIT:  Captures from loopback / own-network interfaces ONLY.
              Bounded captures only (max_packets parameter).
              No default exposure beyond localhost.

DESIGN NOTE:
    This module serves as the Windows fallback for live capture when
    Zeek is not available.  Zeek produces richer, more reliable structured
    output (conn.log with protocol identification, connection tracking, etc.).
    This Scapy version does basic packet-level feature extraction without
    the deep protocol analysis Zeek provides.

    Both approaches are retained to demonstrate engineering judgment in the
    dissertation: Scapy for portability, Zeek for production quality.

ALSO GENERATES:
    A synthetic Zeek conn.log from captured packets, so the Zeek parser
    can be tested/demonstrated even without a Zeek installation.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

from scapy.all import (
    IP, TCP, UDP, ICMP,
    sniff, get_if_list,
    wrpcap,
)


# ---------------------------------------------------------------------------
# Connection tracker — aggregates packets into connection-level records
# ---------------------------------------------------------------------------

class ConnectionTracker:
    """Track individual connections from raw packets.

    Groups packets by (src_ip, dst_ip, src_port, dst_port, proto) 5-tuple
    and produces NSL-KDD-style feature dicts when connections close or
    when explicitly flushed.
    """

    def __init__(self):
        self._connections: dict[str, dict[str, Any]] = {}
        self._completed: list[dict[str, Any]] = []

    @staticmethod
    def _conn_key(pkt) -> str | None:
        """Build a connection key from a packet."""
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else "icmp"
        src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        return f"{ip.src}:{src_port}->{ip.dst}:{dst_port}/{proto}"

    def process_packet(self, pkt) -> None:
        """Process a single packet, updating connection state."""
        key = self._conn_key(pkt)
        if key is None:
            return

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

        # Track TCP flags
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            conn["flags_seen"].add(str(flags))

            # Check for connection completion
            if "F" in str(flags) or "R" in str(flags):
                self._complete_connection(key)

    def _guess_service(self, pkt) -> str:
        """Guess the service from port numbers."""
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
        }
        return service_map.get(port, "other")

    def _derive_flag(self, conn: dict) -> str:
        """Derive NSL-KDD flag from TCP flags seen."""
        flags = conn["flags_seen"]
        if conn["proto"] != "tcp":
            return "SF"  # UDP/ICMP default

        flags_str = " ".join(flags)
        if "S" in flags_str and "A" not in flags_str and "F" not in flags_str:
            return "S0"  # SYN only, no response
        if "R" in flags_str:
            if "S" in flags_str and "A" in flags_str:
                return "RSTO"
            return "REJ"
        if "F" in flags_str and "A" in flags_str:
            return "SF"  # Normal termination
        if "S" in flags_str and "A" in flags_str:
            return "S1"  # Established but not finished
        return "OTH"

    def _complete_connection(self, key: str) -> None:
        """Move a connection from active to completed."""
        if key in self._connections:
            conn = self._connections.pop(key)
            self._completed.append(conn)

    def flush_all(self) -> list[dict[str, Any]]:
        """Complete all active connections and return all as NSL-KDD events."""
        # Move all active connections to completed
        for key in list(self._connections.keys()):
            self._complete_connection(key)

        events = []
        for conn in self._completed:
            events.append(self._conn_to_nsl_event(conn))
        self._completed.clear()
        return events

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

            # Unmapped features (no packet-level equivalent)
            "wrong_fragment": 0, "urgent": 0, "hot": 0,
            "num_failed_logins": 0, "num_compromised": 0,
            "root_shell": 0, "su_attempted": 0, "num_root": 0,
            "num_file_creations": 0, "num_shells": 0,
            "num_access_files": 0, "num_outbound_cmds": 0,
            "is_host_login": 0, "is_guest_login": 0,

            # Connection-level stats (would need sliding window)
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

        # Metadata for UI/logging (not part of the 41 features)
        event["_meta"] = {
            "source": "scapy",
            "src_ip": conn["src_ip"],
            "src_port": conn["src_port"],
            "dst_ip": conn["dst_ip"],
            "dst_port": conn["dst_port"],
            "packets": conn["src_packets"] + conn["dst_packets"],
        }

        return event


# ---------------------------------------------------------------------------
# Synthetic Zeek conn.log generator
# ---------------------------------------------------------------------------

def generate_synthetic_conn_log(
    events: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """Generate a synthetic Zeek conn.log from captured connection events.

    This allows testing the Zeek parser without a Zeek installation.
    The output follows Zeek's standard TSV format with #fields header.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Reverse-map NSL-KDD service back to Zeek service names
    nsl_to_zeek_service = {
        "http": "http", "ftp": "ftp", "ftp_data": "ftp-data",
        "ssh": "ssh", "smtp": "smtp", "pop_3": "pop3",
        "imap4": "imap", "telnet": "telnet", "domain_u": "dns",
        "ntp_u": "ntp", "other": "-",
    }

    # Reverse-map NSL-KDD flag back to Zeek conn_state
    nsl_to_zeek_state = {
        "SF": "SF", "S0": "S0", "REJ": "REJ", "S1": "S1",
        "S2": "S2", "S3": "S3", "RSTO": "RSTO", "RSTR": "RSTR",
        "RSTOS0": "RSTOS0", "SH": "SH", "OTH": "OTH",
    }

    fields = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "service", "duration", "orig_bytes", "resp_bytes",
        "conn_state", "local_orig", "local_resp", "missed_bytes",
        "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
        "resp_ip_bytes", "tunnel_parents",
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        # Zeek header
        f.write("#separator \\x09\n")
        f.write("#set_separator\t,\n")
        f.write("#empty_field\t(empty)\n")
        f.write("#unset_field\t-\n")
        f.write("#path\tconn\n")
        f.write(f"#fields\t{chr(9).join(fields)}\n")
        f.write("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\t"
                "interval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\t"
                "count\tcount\tcount\tcount\tset[string]\n")

        for event in events:
            meta = event.get("_meta", {})
            ts = str(time.time())
            uid = f"C{uuid.uuid4().hex[:12]}"
            orig_h = meta.get("src_ip", "127.0.0.1")
            orig_p = str(meta.get("src_port", 0))
            resp_h = meta.get("dst_ip", "127.0.0.1")
            resp_p = str(meta.get("dst_port", 0))
            proto = event.get("protocol_type", "tcp")
            service = nsl_to_zeek_service.get(event.get("service", "other"), "-")
            duration = str(event.get("duration", 0))
            orig_bytes = str(int(event.get("src_bytes", 0)))
            resp_bytes = str(int(event.get("dst_bytes", 0)))
            conn_state = nsl_to_zeek_state.get(event.get("flag", "OTH"), "OTH")

            row = [
                ts, uid, orig_h, orig_p, resp_h, resp_p,
                proto, service, duration, orig_bytes, resp_bytes,
                conn_state, "-", "-", "0", "-", "0", "0", "0", "0", "-",
            ]
            f.write("\t".join(row) + "\n")

    print(f"  [scapy] Generated synthetic conn.log: {output_path} ({len(events)} records)")
    return output_path


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------

def capture_packets(
    interface: str | None = None,
    max_packets: int = 50,
    timeout: int = 30,
    output_dir: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Capture live packets and return NSL-KDD-compatible events.

    Parameters
    ----------
    interface : str or None
        Network interface to capture from.  None = Scapy default.
    max_packets : int
        Maximum packets to capture (bounded for safety).
    timeout : int
        Capture timeout in seconds (bounded for safety).
    output_dir : str or Path or None
        If provided, save pcap and synthetic conn.log here.

    Returns
    -------
    list[dict]
        NSL-KDD-compatible event dicts with _meta keys.
    """
    max_packets = min(max_packets, 500)  # Safety cap
    timeout = min(timeout, 120)          # Safety cap

    print(f"  [scapy] Starting capture: interface={interface or 'default'} "
          f"max_packets={max_packets} timeout={timeout}s")

    tracker = ConnectionTracker()

    try:
        packets = sniff(
            iface=interface,
            count=max_packets,
            timeout=timeout,
            filter="ip",  # Only IP packets
        )
        print(f"  [scapy] Captured {len(packets)} packets")

        for pkt in packets:
            tracker.process_packet(pkt)

    except PermissionError:
        print("  [scapy] ERROR: Permission denied. Run as administrator for live capture.")
        return []
    except Exception as exc:
        print(f"  [scapy] ERROR: Capture failed: {exc}")
        return []

    events = tracker.flush_all()
    print(f"  [scapy] Extracted {len(events)} connections from packets")

    # Save artifacts if output_dir provided
    if output_dir and events:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save pcap
        try:
            pcap_path = output_dir / "capture.pcap"
            wrpcap(str(pcap_path), packets)
            print(f"  [scapy] Saved pcap: {pcap_path}")
        except Exception as exc:
            print(f"  [scapy] Could not save pcap: {exc}")

        # Generate synthetic Zeek conn.log
        conn_log_path = output_dir / "conn.log"
        generate_synthetic_conn_log(events, conn_log_path)

    return events
