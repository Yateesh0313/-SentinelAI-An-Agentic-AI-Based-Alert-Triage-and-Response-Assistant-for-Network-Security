"""SentinelAI — Zeek conn.log Parser (Phase 14).

Parses Zeek's conn.log TSV output and maps connection records to the
NSL-KDD feature schema used by the SentinelAI ML pipeline.

FIELD MAPPING — Zeek conn.log -> NSL-KDD Features
==================================================

Zeek conn.log has rich structured fields from real network analysis.
NSL-KDD has 41 features from the 1999 DARPA IDS dataset.  The mapping
is partial by design — some NSL-KDD features have no clean Zeek equivalent
and vice versa.

MAPPED (12 features with direct or close Zeek equivalents):
    duration         <- conn.duration (seconds)
    protocol_type    <- conn.proto (tcp/udp/icmp)
    service          <- conn.service (http/dns/ftp/smtp/ssh/ssl/etc.)
    flag             <- conn.conn_state (S0/SF/REJ/RSTO/etc. — close mapping)
    src_bytes        <- conn.orig_bytes (bytes from originator)
    dst_bytes        <- conn.resp_bytes (bytes from responder)
    land             <- derived: 1 if orig_h == resp_h AND orig_p == resp_p
    logged_in        <- derived: 1 if service indicates authenticated session
    count            <- derived: connections to same host in time window
    srv_count        <- derived: connections to same service in time window
    dst_host_count   <- derived: unique dest hosts in time window
    dst_host_srv_count <- derived: unique dest services in time window

NOT MAPPED (set to 0 — no clean Zeek conn.log equivalent):
    wrong_fragment, urgent, hot, num_failed_logins, num_compromised,
    root_shell, su_attempted, num_root, num_file_creations, num_shells,
    num_access_files, num_outbound_cmds, is_host_login, is_guest_login,
    serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate,
    same_srv_rate, diff_srv_rate, srv_diff_host_rate,
    dst_host_same_srv_rate, dst_host_diff_srv_rate,
    dst_host_same_src_port_rate, dst_host_srv_diff_host_rate,
    dst_host_serror_rate, dst_host_srv_serror_rate,
    dst_host_rerror_rate, dst_host_srv_rerror_rate

    NOTE: Some of these COULD be derived from conn.log with a sliding
    window of recent connections (e.g. serror_rate from tracking S0
    connections), but that requires stateful processing beyond simple
    log parsing.  This is documented as a known limitation for the report.

PLATFORM NOTE:
    Zeek does not run natively on Windows.  This parser is designed to
    work with conn.log files produced on a Linux/macOS Zeek installation
    or generated synthetically from Scapy pcap captures.  See
    scapy_capture.py for the live capture fallback on Windows.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Zeek conn_state -> NSL-KDD flag mapping
# ---------------------------------------------------------------------------

# Zeek connection states and their closest NSL-KDD equivalents:
#   S0:   Connection attempt seen, no reply  -> S0 (connection attempt)
#   S1:   Connection established, not finished  -> S1
#   SF:   Normal establishment and termination  -> SF (normal)
#   REJ:  Connection attempt rejected  -> REJ
#   S2:   Established, originator closed, no reply from responder  -> S2
#   S3:   Established, responder closed, no reply from originator  -> S3
#   RSTO: Connection reset by originator  -> RSTO
#   RSTR: Connection reset by responder  -> RSTR
#   RSTOS0: Originator sent SYN then RST  -> RSTOS0
#   RSTRH: Responder sent SYN-ACK then RST  -> RSTRH
#   SH:   Originator sent SYN then FIN  -> SH
#   SHR:  Responder sent SYN-ACK then FIN  -> SHR
#   OTH:  No SYN seen, midstream traffic  -> OTH

ZEEK_STATE_TO_FLAG: dict[str, str] = {
    "S0": "S0",
    "S1": "S1",
    "SF": "SF",
    "REJ": "REJ",
    "S2": "S2",
    "S3": "S3",
    "RSTO": "RSTO",
    "RSTR": "RSTR",
    "RSTOS0": "RSTOS0",
    "RSTRH": "RSTR",
    "SH": "SH",
    "SHR": "SH",
    "OTH": "OTH",
}


# ---------------------------------------------------------------------------
# Zeek service -> NSL-KDD service mapping
# ---------------------------------------------------------------------------

ZEEK_SERVICE_TO_NSL: dict[str, str] = {
    "http": "http",
    "https": "http",
    "ssl": "http",
    "dns": "domain_u",
    "ftp": "ftp",
    "ftp-data": "ftp_data",
    "ssh": "ssh",
    "smtp": "smtp",
    "pop3": "pop_3",
    "imap": "imap4",
    "telnet": "telnet",
    "irc": "IRC",
    "finger": "finger",
    "ntp": "ntp_u",
    "dhcp": "other",
    "krb": "kerberos",
    "dce_rpc": "other",
    "rdp": "other",
    "smb": "other",
    "syslog": "other",
}


# ---------------------------------------------------------------------------
# Zeek conn.log parser
# ---------------------------------------------------------------------------

def parse_conn_log(log_path: str | Path) -> list[dict[str, Any]]:
    """Parse a Zeek conn.log file into a list of connection records.

    Handles both Zeek's native TSV format (with #fields header) and
    plain TSV with standard column names.

    Returns a list of raw Zeek records (dicts with Zeek field names).
    """
    log_path = Path(log_path)
    if not log_path.exists():
        raise FileNotFoundError(f"Zeek conn.log not found: {log_path}")

    records: list[dict[str, Any]] = []
    field_names: list[str] | None = None

    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            # Skip empty lines and comments (except #fields)
            if not line:
                continue
            if line.startswith("#fields"):
                # Parse Zeek header: "#fields\tts\tuid\tid.orig_h\t..."
                field_names = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue

            parts = line.split("\t")

            if field_names is None:
                # Use default Zeek conn.log field order
                field_names = [
                    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                    "id.resp_p", "proto", "service", "duration",
                    "orig_bytes", "resp_bytes", "conn_state", "local_orig",
                    "local_resp", "missed_bytes", "history", "orig_pkts",
                    "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
                    "tunnel_parents",
                ]

            record = {}
            for j, name in enumerate(field_names):
                if j < len(parts):
                    record[name] = parts[j]
                else:
                    record[name] = "-"
            records.append(record)

    return records


def _safe_float(val: str, default: float = 0.0) -> float:
    """Convert a Zeek field value to float, handling '-' (unset)."""
    if val in ("-", "(empty)", ""):
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _safe_int(val: str, default: int = 0) -> int:
    """Convert a Zeek field value to int, handling '-' (unset)."""
    if val in ("-", "(empty)", ""):
        return default
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def zeek_record_to_nsl_event(record: dict[str, str]) -> dict[str, Any]:
    """Map a single Zeek conn.log record to NSL-KDD feature dict.

    Parameters
    ----------
    record : dict
        A Zeek conn.log record (field names as keys, string values).

    Returns
    -------
    dict
        NSL-KDD-compatible feature dict with 41 features + metadata.
        Unmapped features are set to 0.
    """
    # --- Direct mappings ---
    duration = _safe_float(record.get("duration", "-"))
    proto = record.get("proto", "tcp").lower()
    src_bytes = _safe_float(record.get("orig_bytes", "-"))
    dst_bytes = _safe_float(record.get("resp_bytes", "-"))

    # Protocol type: Zeek uses tcp/udp/icmp
    protocol_type = proto if proto in ("tcp", "udp", "icmp") else "tcp"

    # Service: map Zeek service names to NSL-KDD equivalents
    zeek_service = record.get("service", "-").lower()
    if zeek_service in ("-", "(empty)", ""):
        # No service identified — use "other"
        service = "other"
    else:
        # Handle comma-separated services (e.g. "ssl,http")
        first_service = zeek_service.split(",")[0].strip()
        service = ZEEK_SERVICE_TO_NSL.get(first_service, "other")

    # Flag: map Zeek connection state
    conn_state = record.get("conn_state", "-")
    flag = ZEEK_STATE_TO_FLAG.get(conn_state, "OTH")

    # Land: same source and dest IP+port
    orig_h = record.get("id.orig_h", "")
    resp_h = record.get("id.resp_h", "")
    orig_p = record.get("id.orig_p", "0")
    resp_p = record.get("id.resp_p", "0")
    land = 1 if (orig_h == resp_h and orig_p == resp_p) else 0

    # Logged in: heuristic based on service indicating auth session
    auth_services = {"ssh", "telnet", "ftp", "pop_3", "imap4", "kerberos"}
    logged_in = 1 if (service in auth_services and flag == "SF") else 0

    # --- Build the 41-feature NSL-KDD event ---
    event: dict[str, Any] = {
        # Mapped features
        "duration": duration,
        "protocol_type": protocol_type,
        "service": service,
        "flag": flag,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": land,
        "logged_in": logged_in,

        # Unmapped features (set to 0 — no clean Zeek conn.log equivalent)
        "wrong_fragment": 0,
        "urgent": 0,
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

        # Connection-level stats (could be derived from sliding window)
        "count": 0,
        "srv_count": 0,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 0.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,

        # Host-level stats (require sliding window)
        "dst_host_count": 0,
        "dst_host_srv_count": 0,
        "dst_host_same_srv_rate": 0.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }

    # --- Metadata (not part of the 41 features, for UI/logging) ---
    event["_meta"] = {
        "source": "zeek",
        "src_ip": orig_h,
        "src_port": _safe_int(orig_p),
        "dst_ip": resp_h,
        "dst_port": _safe_int(resp_p),
        "zeek_uid": record.get("uid", ""),
        "zeek_conn_state": conn_state,
        "zeek_service": zeek_service,
        "timestamp": record.get("ts", ""),
    }

    return event


def parse_conn_log_to_events(
    log_path: str | Path,
) -> list[dict[str, Any]]:
    """Parse a Zeek conn.log and return NSL-KDD-compatible events.

    This is the main entry point for the Zeek integration.

    Parameters
    ----------
    log_path : str or Path
        Path to a Zeek conn.log file.

    Returns
    -------
    list[dict]
        Each dict is a 41-feature NSL-KDD event with a _meta key
        containing Zeek-specific metadata (source IPs, etc.).
    """
    records = parse_conn_log(log_path)
    events = [zeek_record_to_nsl_event(r) for r in records]
    print(f"  [zeek] Parsed {len(events)} connection records from {Path(log_path).name}")
    return events
