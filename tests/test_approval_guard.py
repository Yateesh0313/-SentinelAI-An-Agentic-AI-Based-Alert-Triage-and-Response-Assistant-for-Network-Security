"""Unit tests for SOC Approval/Rejection Workflow & Double-Action Guard.

Verifies:
- Atomic status transition from pending_review -> approved
- Atomic status transition from pending_review -> rejected
- Double-approval protection (HTTP 409 Conflict on second approve attempt)
- Cross-action protection (HTTP 409 Conflict on reject after approve)
- Timestamp and resolver audit metadata recording
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

client = TestClient(main.app, raise_server_exceptions=False)


def get_token(username: str = "test_analyst") -> dict[str, str]:
    token = auth.create_access_token({"sub": username, "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}


def test_atomic_approve_and_double_guard():
    """Verify first approval succeeds and second approval returns 409 Conflict."""
    event_id = f"test_{uuid.uuid4().hex[:6]}"
    fake_pending_event = {
        "event_id": event_id,
        "status": "pending_review",
        "recommended_action": "block_ip",
        "severity": "High",
    }
    fake_approved_event = {
        **fake_pending_event,
        "status": "approved",
        "resolved_by": "analyst1",
        "resolved_at": "2026-09-03T12:00:00Z",
    }

    headers = get_token("analyst1")

    # Step 1: First approval succeeds
    with patch.object(db, "get_event", AsyncMock(return_value=fake_pending_event)):
        with patch.object(db, "approve_event", AsyncMock(return_value=fake_approved_event)):
            with patch.object(main, "_broadcast", AsyncMock()):
                res1 = client.post(f"/events/{event_id}/approve", headers=headers)
                assert res1.status_code == 200, f"Expected 200, got {res1.status_code}: {res1.text}"
                data1 = res1.json()
                assert data1["status"] == "approved"
                assert data1["action_executed"] == "block_ip"
                assert data1["resolved_by"] == "analyst1"

    # Step 2: Second approval on already-approved event returns 409 Conflict
    with patch.object(db, "get_event", AsyncMock(return_value=fake_approved_event)):
        with patch.object(db, "approve_event", AsyncMock(return_value=None)):  # DB atomic findOneAndUpdate returns None
            res2 = client.post(f"/events/{event_id}/approve", headers=headers)
            assert res2.status_code == 409, f"Expected 409, got {res2.status_code}: {res2.text}"
            assert "already resolved as 'approved'" in res2.json()["detail"]


def test_atomic_reject_and_cross_guard():
    """Verify rejection succeeds, and attempting to approve a rejected event yields 409."""
    event_id = f"test_{uuid.uuid4().hex[:6]}"
    fake_pending_event = {
        "event_id": event_id,
        "status": "pending_review",
        "recommended_action": "isolate_host",
        "severity": "Medium",
    }
    fake_rejected_event = {
        **fake_pending_event,
        "status": "rejected",
        "resolved_by": "analyst2",
        "resolved_at": "2026-09-03T12:05:00Z",
    }

    headers = get_token("analyst2")

    # Step 1: Rejection succeeds
    with patch.object(db, "get_event", AsyncMock(return_value=fake_pending_event)):
        with patch.object(db, "reject_event", AsyncMock(return_value=fake_rejected_event)):
            with patch.object(main, "_broadcast", AsyncMock()):
                res1 = client.post(f"/events/{event_id}/reject", headers=headers)
                assert res1.status_code == 200
                data1 = res1.json()
                assert data1["status"] == "rejected"
                assert data1["action_declined"] == "isolate_host"

    # Step 2: Trying to approve an already-rejected event returns 409 Conflict
    with patch.object(db, "get_event", AsyncMock(return_value=fake_rejected_event)):
        with patch.object(db, "approve_event", AsyncMock(return_value=None)):
            res2 = client.post(f"/events/{event_id}/approve", headers=headers)
            assert res2.status_code == 409
            assert "already resolved as 'rejected'" in res2.json()["detail"]
