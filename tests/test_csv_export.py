"""Unit and integration tests for CSV log export pipeline (Phase 23).

Tests:
1. convert_logs_to_csv flattening and quoting behavior.
2. Excel-compatibility (utf-8-sig BOM encoding, comma preservation).
3. backend.csv_exporter service execution and file naming in data/csv/.
4. FastAPI endpoints: /logs/export/csv/{source}, /logs/download-csv, /logs/csv/list.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sys
import pytest

# Ensure scripts and backend are in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
BACKEND_DIR = PROJECT_ROOT / "backend"

for d in (SCRIPTS_DIR, BACKEND_DIR):
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))

from convert_logs_to_csv import flatten_json, load_jsonlines, convert
from csv_exporter import (
    CSV_DIR,
    append_honeypot_log,
    export_honeypot_csv,
    export_suricata_csv,
    list_exported_csvs,
    get_latest_csv,
)
from fastapi.testclient import TestClient
import main


# ---------------------------------------------------------------------------
# Test 1: Flattening logic preservation
# ---------------------------------------------------------------------------

def test_flatten_json_nested_and_lists():
    """Verify nested objects and lists flatten according to convert_logs_to_csv logic."""
    raw = {
        "src_ip": "192.168.1.100",
        "alert": {
            "signature": "ET SCAN Nmap Scripting Engine, Detected",
            "severity": 1,
            "category": "Web Application Attack",
            "metadata": {
                "confidence": ["High"],
                "tags": ["scan", "recon"],
            }
        },
        "tags": ["alpha", "beta"],
    }
    flat = flatten_json(raw)
    assert flat["src_ip"] == "192.168.1.100"
    assert flat["alert_signature"] == "ET SCAN Nmap Scripting Engine, Detected"
    assert flat["alert_severity"] == 1
    assert flat["alert_category"] == "Web Application Attack"
    assert flat["alert_metadata_confidence"] == "High"
    assert flat["alert_metadata_tags"] == "scan; recon"
    assert flat["tags"] == "alpha; beta"


# ---------------------------------------------------------------------------
# Test 2: File conversion with quotes, commas, and UTF-8 BOM encoding
# ---------------------------------------------------------------------------

def test_convert_csv_quoting_and_bom(tmp_path: Path):
    """Verify converted CSV contains UTF-8 BOM and properly quotes fields with commas."""
    test_log = tmp_path / "test_eve.json"
    records = [
        {
            "timestamp": "2026-09-19T12:00:00Z",
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "src_port": 12345,
            "dest_ip": "10.0.0.2",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "ET SCAN User-Agent, Contains Comma, Extra Text",
                "category": "Attempted Information Leak",
                "severity": 2,
            }
        },
        {
            "timestamp": "2026-09-19T12:00:01Z",
            "event_type": "flow",
            "src_ip": "10.0.0.1",
        }
    ]
    with open(test_log, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    out_csv = tmp_path / "output.csv"
    convert(str(test_log), str(out_csv), source="suricata", alerts_only=True)

    # 1. Check raw byte content begins with UTF-8 BOM (\xef\xbb\xbf)
    raw_bytes = out_csv.read_bytes()
    assert raw_bytes.startswith(b"\xef\xbb\xbf"), "CSV file must start with UTF-8 BOM for Excel compatibility"

    # 2. Check reader correctly parses the quoted comma
    with open(out_csv, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 1  # only alert row kept
        row = rows[0]
        assert row["src_ip"] == "10.0.0.1"
        assert row["alert_signature"] == "ET SCAN User-Agent, Contains Comma, Extra Text"
        # Priority columns should be present
        assert "timestamp" in row
        assert "dest_ip" in row


# ---------------------------------------------------------------------------
# Test 3: Backend exporter service
# ---------------------------------------------------------------------------

def test_csv_exporter_service(tmp_path: Path):
    """Verify csv_exporter functions create expected filenames in data/csv/."""
    # Write a test honeypot log
    hp_event = {
        "timestamp": "2026-09-19T12:30:00Z",
        "event_type": "honeypot_probe",
        "src_ip": "198.51.100.22",
        "src_port": 55123,
        "dst_port": 8899,
        "probe_text": "GET /test HTTP/1.1",
        "probe_bytes_len": 18,
        "connection_id": 99,
        "severity": "High",
        "risk_score": 85,
        "triage": "Suspicious honeypot probe",
    }
    append_honeypot_log(hp_event)

    csv_path = export_honeypot_csv()
    assert csv_path.exists()
    assert csv_path.name.startswith("honeypot_events_")
    assert csv_path.name.endswith(".csv")
    assert csv_path.parent == CSV_DIR

    # Verify latest CSV finder
    latest = get_latest_csv("honeypot")
    assert latest is not None
    assert latest.name.startswith("honeypot_events_")

    # Verify list files
    file_list = list_exported_csvs()
    assert any(f["filename"] == csv_path.name for f in file_list)


# ---------------------------------------------------------------------------
# Test 4: FastAPI endpoints
# ---------------------------------------------------------------------------

from auth import create_access_token


def test_fastapi_export_endpoints():
    """Verify FastAPI /logs/export/csv and list endpoints."""
    client = TestClient(main.app)
    token = create_access_token({"sub": "test_admin", "role": "admin"})
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Export Suricata CSV
    res_suri = client.get("/logs/export/csv/suricata", headers=headers)
    assert res_suri.status_code == 200
    assert "text/csv" in res_suri.headers["content-type"]
    assert "attachment" in res_suri.headers["content-disposition"]
    assert "suricata_alerts_" in res_suri.headers["content-disposition"]

    # 2. Export Honeypot CSV
    res_hp = client.get("/logs/export/csv/honeypot", headers=headers)
    assert res_hp.status_code == 200
    assert "text/csv" in res_hp.headers["content-type"]
    assert "honeypot_events_" in res_hp.headers["content-disposition"]

    # 3. Alias /logs/download-csv
    res_alias = client.get("/logs/download-csv?source=suricata", headers=headers)
    assert res_alias.status_code == 200
    assert "text/csv" in res_alias.headers["content-type"]

    # 4. List CSVs
    res_list = client.get("/logs/csv/list", headers=headers)
    assert res_list.status_code == 200
    data = res_list.json()
    assert "count" in data
    assert "files" in data
    assert data["count"] > 0

    # 5. Invalid source
    res_err = client.get("/logs/export/csv/invalid_source", headers=headers)
    assert res_err.status_code == 400
