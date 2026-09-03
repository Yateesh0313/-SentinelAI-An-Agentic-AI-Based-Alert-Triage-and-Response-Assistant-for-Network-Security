"""Unit tests for ATT&CK Rule Heuristics and YARA Signatures.

Verifies:
- Deterministic heuristic mapping from NSL-KDD network events to MITRE ATT&CK techniques
- YARA signature rules compilation and detection accuracy
- True negative checks: clean traffic produces zero technique/signature flags
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "agents"))
sys.path.insert(0, str(_PROJECT_ROOT / "ml" / "signatures"))

from attack_mapping import map_attack_techniques
from matcher import match_signatures


# ---------------------------------------------------------------------------
# MITRE ATT&CK Heuristic Mapping Tests
# ---------------------------------------------------------------------------

def test_attack_dos_t1498():
    """SYN flood patterns must map to T1498 (Network Denial of Service)."""
    event = {
        "serror_rate": 0.95,
        "srv_serror_rate": 0.90,
        "count": 150,
        "flag": "S0",
    }
    techniques = map_attack_techniques(event)
    ids = [t["id"] for t in techniques]
    assert "T1498" in ids
    match = next(t for t in techniques if t["id"] == "T1498")
    assert match["name"] == "Network Denial of Service"


def test_attack_port_scan_t1046():
    """High diff_srv_rate with low duration must map to T1046 (Network Service Discovery)."""
    event = {
        "diff_srv_rate": 0.85,
        "dst_host_diff_srv_rate": 0.60,
        "duration": 0.1,
        "count": 35,
    }
    techniques = map_attack_techniques(event)
    ids = [t["id"] for t in techniques]
    assert "T1046" in ids


def test_attack_brute_force_t1110():
    """Repeated failed logins must map to T1110 (Brute Force)."""
    event = {
        "num_failed_logins": 5,
    }
    techniques = map_attack_techniques(event)
    ids = [t["id"] for t in techniques]
    assert "T1110" in ids


def test_attack_exfiltration_t1041():
    """High outbound data with low inbound response must map to T1041 (Exfiltration)."""
    event = {
        "src_bytes": 85000,
        "dst_bytes": 200,
    }
    techniques = map_attack_techniques(event)
    ids = [t["id"] for t in techniques]
    assert "T1041" in ids


def test_attack_clean_traffic():
    """Normal web traffic must not trigger any malicious technique mappings."""
    event = {
        "duration": 1,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 250,
        "dst_bytes": 1200,
        "count": 5,
        "serror_rate": 0.0,
        "diff_srv_rate": 0.0,
        "num_failed_logins": 0,
    }
    techniques = map_attack_techniques(event)
    assert len(techniques) == 0


# ---------------------------------------------------------------------------
# YARA Signature Matcher Tests
# ---------------------------------------------------------------------------

def test_yara_telnet_root_access():
    """Telnet session yielding root shell must trigger Telnet_Root_Access signature."""
    event = {
        "service": "telnet",
        "root_shell": 1,
    }
    matches = match_signatures(event)
    rules = [m["rule"] for m in matches]
    assert "Telnet_Root_Access" in rules
    target = next(m for m in matches if m["rule"] == "Telnet_Root_Access")
    assert target["severity"] == "critical"


def test_yara_ftp_failed_connection():
    """FTP connection stuck in S0 state must trigger FTP_Failed_Connection signature."""
    event = {
        "service": "ftp",
        "flag": "S0",
    }
    matches = match_signatures(event)
    rules = [m["rule"] for m in matches]
    assert "FTP_Failed_Connection" in rules


def test_yara_icmp_unusual_bytes():
    """ICMP traffic with large source payload must trigger ICMP_Unusual_Bytes signature."""
    event = {
        "protocol_type": "icmp",
        "src_bytes": 1024,
    }
    matches = match_signatures(event)
    rules = [m["rule"] for m in matches]
    assert "ICMP_Unusual_Bytes" in rules


def test_yara_clean_event():
    """Standard HTTP traffic must not match any YARA intrusion signatures."""
    event = {
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 300,
        "dst_bytes": 5000,
        "root_shell": 0,
        "num_failed_logins": 0,
    }
    matches = match_signatures(event)
    assert len(matches) == 0
