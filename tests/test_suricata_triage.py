"""Test Suricata alert processing through heuristic_triage with context."""
from __future__ import annotations

import sys
from pathlib import Path

_AGENTS_DIR = Path(__file__).resolve().parent.parent / "agents"
if str(_AGENTS_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTS_DIR))

from pipeline import heuristic_triage


def test_suricata_heuristic_triage_scanning():
    context = {
        "suricata_meta": {
            "signature": "ET SCAN Nmap Scripting Engine",
            "category": "Attempted Information Leak",
            "severity": 2,
            "severity_label": "High",
        },
        "network_meta": {
            "src_ip": "192.168.1.100",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "proto": "TCP",
        },
    }
    result = heuristic_triage({}, context=context)
    assert result["recommended_action"] != "no_action"
    assert "scanning" in result["triage"].lower()

