"""End-to-End Integration Test for SentinelAI Alert Lifecycle (Phase 20).

Validates the full alert workflow:
1. POST /detect (ML classification & YARA signature matching)
2. POST /triage (Agentic analysis + IP enrichment + Formula risk scoring + MongoDB persistence)
3. POST /events/{event_id}/approve (SOC analyst approval)
4. GET /events/{event_id} (Retrieval & schema completeness validation)
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest
from fastapi.testclient import TestClient

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "backend"))

import auth
import database as db
import main

import joblib

client = TestClient(main.app, raise_server_exceptions=False)


def _ensure_models():
    if main._model is None:
        main._model = joblib.load(_PROJECT_ROOT / "ml" / "results" / "classical_baseline_model.joblib")
        main._scaler = joblib.load(_PROJECT_ROOT / "ml" / "data" / "processed" / "scaler.joblib")
        main._encoder = joblib.load(_PROJECT_ROOT / "ml" / "data" / "processed" / "encoder.joblib")


def get_token(username: str = "lead_analyst") -> dict[str, str]:
    token = auth.create_access_token({"sub": username, "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}


def test_full_pipeline_event_lifecycle():
    """Run an anomaly through detection, triage, risk scoring, and approval."""
    _ensure_models()
    # Anomaly payload: SYN flood pattern
    sample_event = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "REJ",
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
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
        "count": 229,
        "srv_count": 10,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 1.0,
        "srv_rerror_rate": 1.0,
        "same_srv_rate": 0.04,
        "diff_srv_rate": 0.06,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 10,
        "dst_host_same_srv_rate": 0.04,
        "dst_host_diff_srv_rate": 0.06,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 1.0,
        "dst_host_srv_rerror_rate": 1.0,
    }

    # 1. Step 1: Detect
    detect_resp = client.post("/detect", json=sample_event)
    assert detect_resp.status_code == 200, f"Detect failed: {detect_resp.text}"
    detect_data = detect_resp.json()
    assert detect_data["prediction"] == "anomaly"
    assert isinstance(detect_data["confidence"], float)

    # 2. Step 2: Full Triage (detect -> agents -> enrichment -> risk score -> store)
    # Mock LLM network call to guarantee fast, deterministic offline execution
    mock_agent_result = {
        "triage": "Repeated connection attempts with REJ flag indicate automated reconnaissance or scanning.",
        "severity": "High",
        "severity_justification": "High volume of rejected connections targeting private network services.",
        "recommended_action": "block_ip",
        "attack_techniques": [{"id": "T1046", "name": "Network Service Discovery"}],
    }

    stored_doc = {}
    active_event_id = ""

    async def mock_insert_event(event_dict, eid):
        nonlocal stored_doc, active_event_id
        active_event_id = eid
        stored_doc = {
            **event_dict,
            "event_id": eid,
            "status": "pending_review",
        }
        return eid

    async def mock_get_event(eid):
        if eid == active_event_id:
            return stored_doc
        return None

    async def mock_approve_event(eid, resolved_by):
        nonlocal stored_doc
        if eid == active_event_id and stored_doc.get("status") == "pending_review":
            stored_doc["status"] = "approved"
            stored_doc["resolved_by"] = resolved_by
            stored_doc["resolved_at"] = "2026-09-03T12:00:00Z"
            stored_doc["action_executed"] = stored_doc.get("recommended_action")
            return stored_doc
        return None

    with patch("pipeline.run_pipeline", return_value=mock_agent_result):
        with patch.object(db, "insert_event", side_effect=mock_insert_event):
            triage_resp = client.post("/triage", json=sample_event)
            assert triage_resp.status_code == 200, f"Triage failed: {triage_resp.text}"
            triage_data = triage_resp.json()
            test_event_id = triage_data["event_id"]
            assert test_event_id is not None
            assert triage_data["severity"] == "High"
            assert "risk_score" in triage_data
            assert triage_data["risk_classification"] in ("MEDIUM", "HIGH", "CRITICAL")
            assert "ml_confidence" in triage_data["risk_signals"]

    # 3. Step 3: SOC Analyst Approval
    headers = get_token("lead_analyst")
    with patch.object(db, "get_event", side_effect=mock_get_event):
        with patch.object(db, "approve_event", side_effect=mock_approve_event):
            with patch.object(main, "_broadcast", AsyncMock()):
                approve_resp = client.post(f"/events/{test_event_id}/approve", headers=headers)
                assert approve_resp.status_code == 200, f"Approve failed: {approve_resp.text}"
                approve_data = approve_resp.json()
                assert approve_data["status"] == "approved"
                assert approve_data["resolved_by"] == "lead_analyst"
                assert approve_data["action_executed"] == "block_ip"

    # 4. Step 4: Verify complete stored document schema
    with patch.object(db, "get_event", side_effect=mock_get_event):
        get_resp = client.get(f"/events/{test_event_id}")
        assert get_resp.status_code == 200
        final_doc = get_resp.json()["data"]

        # Assert all required fields are present
        assert final_doc["event_id"] == test_event_id
        assert final_doc["status"] == "approved"
        assert final_doc["resolved_by"] == "lead_analyst"
        assert final_doc["resolved_at"] is not None
        assert final_doc["recommended_action"] == "block_ip"
        assert final_doc["severity"] == "High"
        assert 0 <= final_doc["risk_score"] <= 100
        assert final_doc["risk_classification"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert all(k in final_doc["risk_signals"] for k in [
            "ml_confidence", "reputation", "signature", "attack", "source"
        ])

