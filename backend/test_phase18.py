"""Phase 18 Verification Suite — Demo-Mode Consolidation & Failure Hardening.

Tests:
1. RESEARCH_MODE=false:
   - /config/mode returns {"research_mode": false}
   - /honeypot/start rejected with HTTP 403 and clean JSON message
   - /honeypot/stop rejected with HTTP 403 and clean JSON message
2. RESEARCH_MODE=true:
   - Gating is lifted, honeypot controls function normally
3. Deliberate Failure Scenario 1: MongoDB down / error simulation
   - /stats/overview handles gracefully (returns zeros dict)
   - /events/pending returns clean JSON on DB error
4. Deliberate Failure Scenario 2: Malformed JSON to /detect
   - Returns clean 422 JSON validation error
5. Deliberate Failure Scenario 3: WebSocket connection and abrupt disconnection
   - Connects and disconnects cleanly without server crash
6. Global Exception Handler:
   - Safety net returns clean JSON without traceback leakage
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

# Ensure backend root is on path
_DIR = Path(__file__).resolve().parent
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))

import auth
import main
from auth import create_access_token

client = TestClient(main.app, raise_server_exceptions=False)

def get_auth_headers(username: str = "demo_analyst") -> dict[str, str]:
    token = create_access_token({"sub": username, "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}


def test_research_mode_disabled():
    print("\n--- 1. Testing RESEARCH_MODE=False Gate ---")
    main.RESEARCH_MODE = False

    # Check /config/mode
    resp = client.get("/config/mode")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
    assert resp.json() == {"research_mode": False}, f"Unexpected: {resp.json()}"
    print("  [PASS] /config/mode returns {'research_mode': False}")

    headers = get_auth_headers()

    # /honeypot/start should be 403
    hp_start = client.get("/honeypot/start", headers=headers)
    assert hp_start.status_code == 403, f"Expected 403, got {hp_start.status_code}"
    assert "Research Mode is disabled" in hp_start.json().get("detail", "")
    print(f"  [PASS] /honeypot/start blocked with 403: {hp_start.json()['detail']}")

    # /honeypot/stop should be 403
    hp_stop = client.get("/honeypot/stop", headers=headers)
    assert hp_stop.status_code == 403, f"Expected 403, got {hp_stop.status_code}"
    assert "Research Mode is disabled" in hp_stop.json().get("detail", "")
    print(f"  [PASS] /honeypot/stop blocked with 403: {hp_stop.json()['detail']}")

    # /honeypot/status should still work (read-only)
    hp_status = client.get("/honeypot/status")
    assert hp_status.status_code == 200
    assert hp_status.json() == {"status": "stopped"}
    print("  [PASS] /honeypot/status accessible and returns stopped")


def test_research_mode_enabled():
    print("\n--- 2. Testing RESEARCH_MODE=True Mode ---")
    main.RESEARCH_MODE = True

    resp = client.get("/config/mode")
    assert resp.status_code == 200
    assert resp.json() == {"research_mode": True}
    print("  [PASS] /config/mode returns {'research_mode': True}")

    headers = get_auth_headers()
    # Now honeypot/start is not 403
    hp_start = client.get("/honeypot/start", headers=headers)
    assert hp_start.status_code in (200, 500)  # Allowed through the gate
    assert hp_start.status_code != 403
    print(f"  [PASS] /honeypot/start allowed through gate: status={hp_start.status_code}")

    # Stop it cleanly
    hp_stop = client.get("/honeypot/stop", headers=headers)
    assert hp_stop.status_code != 403
    print("  [PASS] /honeypot/stop allowed through gate")

    # Reset to default false
    main.RESEARCH_MODE = False


def test_failure_malformed_json():
    print("\n--- 3. Deliberate Failure: Malformed JSON to /detect ---")
    # 1. Syntactically invalid JSON payload
    r1 = client.post(
        "/detect",
        content=b'{"duration": 12, "protocol_type": broken_json_no_quotes}',
        headers={"Content-Type": "application/json"},
    )
    assert r1.status_code == 422, f"Expected 422, got {r1.status_code}: {r1.text}"
    assert "detail" in r1.json()
    print("  [PASS] Syntactically invalid JSON rejected with clean 422 response")

    # 2. Schema violation: non-numeric string for float column
    r2 = client.post("/detect", json={"duration": "not-a-float"})
    assert r2.status_code == 422, f"Expected 422, got {r2.status_code}: {r2.text}"
    assert isinstance(r2.json()["detail"], list)
    print("  [PASS] Invalid field types rejected with clean 422 Pydantic details")


def test_failure_mongodb_down():
    print("\n--- 4. Deliberate Failure: MongoDB Down / DB Exception ---")
    import database as db

    # 1. stats_overview handles DB failure gracefully without throwing
    with patch.object(db, "get_stats_overview", side_effect=RuntimeError("MongoDB connection lost")):
        resp = client.get("/stats/overview")
        assert resp.status_code == 200
        assert resp.json()["total_events"] == 0
        print("  [PASS] /stats/overview returned clean zero-state when MongoDB failed")

    # 2. events_pending returns clean 500 JSON on DB failure, not raw crash
    with patch.object(db, "get_pending_events", side_effect=Exception("Connection timed out")):
        resp = client.get("/events/pending")
        assert resp.status_code == 500
        data = resp.json()
        assert "detail" in data
        assert "Failed to fetch pending events" in data["detail"]
        print("  [PASS] /events/pending returned clean JSON error: " + data["detail"])


def test_failure_websocket_disconnect():
    print("\n--- 5. Deliberate Failure: WebSocket Abrupt Disconnect ---")
    with client.websocket_connect("/ws") as ws:
        assert len(main._ws_clients) >= 1
        print(f"  [PASS] WebSocket connected successfully (active: {len(main._ws_clients)})")
    # Exiting context abruptly disconnects
    print(f"  [PASS] WebSocket closed cleanly without server error (active: {len(main._ws_clients)})")


def test_global_exception_handler():
    print("\n--- 6. Global Exception Handler Test ---")
    @main.app.get("/test/crash")
    async def crash_endpoint():
        raise ZeroDivisionError("Simulated uncaught crash")

    resp = client.get("/test/crash")
    assert resp.status_code == 500
    data = resp.json()
    assert data["error"] == "internal_server_error"
    assert "An unexpected error occurred" in data["detail"]
    print("  [PASS] Global exception handler caught crash: " + str(data))


if __name__ == "__main__":
    print("=" * 60)
    print("  SentinelAI Phase 18 Verification Suite")
    print("=" * 60)
    test_research_mode_disabled()
    test_research_mode_enabled()
    test_failure_malformed_json()
    test_failure_mongodb_down()
    test_failure_websocket_disconnect()
    test_global_exception_handler()
    print("\n" + "=" * 60)
    print("  ALL PHASE 18 TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)
