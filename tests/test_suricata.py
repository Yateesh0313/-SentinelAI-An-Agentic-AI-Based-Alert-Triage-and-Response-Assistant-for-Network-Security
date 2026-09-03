"""Tests for Phase 22 Suricata IDS Ingestion and Pipeline Integration."""

import asyncio
import sys
from pathlib import Path

# Add ml/live_capture and backend to path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "ml" / "live_capture"))
sys.path.insert(0, str(_ROOT / "backend"))

from suricata_ingest import SuricataIngestor, _SEVERITY_MAP, _CATEGORY_TO_TACTIC
from risk_scoring import calculate_risk_score, _SOURCE_MAP


def test_severity_mapping():
    """Verify Suricata severity integers map to correct human-readable tiers."""
    assert _SEVERITY_MAP[1] == "Critical"
    assert _SEVERITY_MAP[2] == "High"
    assert _SEVERITY_MAP[3] == "Medium"
    assert _SEVERITY_MAP[4] == "Low"


def test_source_map_suricata_weight():
    """Verify Suricata source weight is 0.80 (high-confidence signature detection)."""
    assert "suricata" in _SOURCE_MAP
    assert _SOURCE_MAP["suricata"] == 0.80
    # Suricata (0.80) should sit between honeypot (1.0) and live_capture (0.60)
    assert _SOURCE_MAP["honeypot"] > _SOURCE_MAP["suricata"] > _SOURCE_MAP["live_capture"]


def test_build_event_structure():
    """Verify SuricataIngestor._build_event generates expected schema."""
    ingestor = SuricataIngestor()
    ingestor._alert_count = 1

    sample_record = {
        "timestamp": "2026-09-03T14:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.105",
        "src_port": 54321,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "proto": "TCP",
    }
    sample_alert = {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2024897,
        "rev": 3,
        "signature": "ET SCAN Nmap Scripting Engine User-Agent",
        "category": "Attempted Information Leak",
        "severity": 2,
    }

    event = ingestor._build_event(sample_record, sample_alert)

    assert event["source"] == "suricata"
    assert event["prediction"] == "suricata_alert"
    assert event["confidence"] == 1.0
    assert event["event_index"] == 1

    meta = event["suricata_meta"]
    assert meta["signature"] == "ET SCAN Nmap Scripting Engine User-Agent"
    assert meta["signature_id"] == 2024897
    assert meta["severity"] == 2
    assert meta["severity_label"] == "High"
    assert meta["category"] == "Attempted Information Leak"
    assert meta["tactic"] == "Discovery"

    net = event["network_meta"]
    assert net["src_ip"] == "192.168.1.105"
    assert net["dst_ip"] == "10.0.0.5"
    assert net["dst_port"] == 80
    assert net["proto"] == "TCP"

    raw = event["raw_event"]
    assert raw["service"] == "http"
    assert raw["protocol_type"] == "tcp"


def test_risk_scoring_suricata_alert():
    """Verify calculate_risk_score calculates expected score for Suricata alert."""
    suricata_event = {
        "prediction": "suricata_alert",
        "confidence": 1.0,
        "source": "suricata",
        "severity": "High",
        "signature_matches": [{"rule": "test_sig", "severity": "HIGH", "description": "test"}],
        "attack_techniques": [{"id": "T1046", "name": "Network Service Scanning"}],
        "ip_enrichment": {
            "ip_type": "real",
            "reputation": {"abuse_confidence_score": 75},
        },
    }

    result = calculate_risk_score(suricata_event)
    assert "risk_score" in result
    assert "risk_classification" in result
    assert result["risk_score"] >= 70
    assert result["risk_classification"] in ("HIGH", "CRITICAL")
    assert result["risk_signals"]["source"] == 0.80


def test_process_line_alert_dispatch():
    """Verify _process_line parses JSON and triggers on_alert callback."""
    dispatched = []

    async def mock_callback(event):
        dispatched.append(event)

    ingestor = SuricataIngestor(on_alert=mock_callback)

    valid_alert_line = (
        '{"timestamp":"2026-09-03T14:00:00.000000+0000","event_type":"alert",'
        '"src_ip":"192.168.1.50","src_port":4444,"dest_ip":"192.168.1.1","dest_port":22,"proto":"TCP",'
        '"alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":20,'
        '"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":1}}'
    )

    non_alert_line = (
        '{"timestamp":"2026-09-03T14:00:00.000000+0000","event_type":"stats","stats":{"uptime":10}}'
    )

    # Process non-alert
    asyncio.run(ingestor._process_line(non_alert_line))
    assert len(dispatched) == 0

    # Process alert
    asyncio.run(ingestor._process_line(valid_alert_line))
    assert len(dispatched) == 1
    assert dispatched[0]["suricata_meta"]["signature"] == "ET SCAN Potential SSH Scan"
    assert dispatched[0]["suricata_meta"]["severity_label"] == "Critical"


import pytest

@pytest.mark.skipif(
    not Path(SuricataIngestor.DEFAULT_BIN).exists() or not Path(r"C:\Users\User\suricata\nmap_external_test.pcap").exists(),
    reason="Suricata binary or test PCAP not installed",
)
def test_suricata_pcap_replay_end_to_end(tmp_path):
    """Verify live Suricata subprocess replays PCAP and triggers on_alert callback."""
    alerts = []

    async def on_alert(event):
        alerts.append(event)

    async def run_test():
        ingestor = SuricataIngestor(
            pcap_file=r"C:\Users\User\suricata\nmap_external_test.pcap",
            log_dir=str(tmp_path),
            on_alert=on_alert,
        )
        status = await ingestor.start()
        assert status["status"] == "started"

        # Wait for processing to complete
        for _ in range(60):
            if not ingestor.running:
                break
            await asyncio.sleep(0.5)

        await ingestor.stop()

    asyncio.run(run_test())

    assert len(alerts) >= 1
    assert alerts[0]["source"] == "suricata"
    assert alerts[0]["suricata_meta"]["signature_id"] == 2009359
    assert alerts[0]["suricata_meta"]["severity_label"] == "Critical"
    assert alerts[0]["suricata_meta"]["tactic"] == "Initial Access"

