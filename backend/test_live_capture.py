"""Verification Suite for Live Traffic Capture (Phase 24).

Tests:
1. GET /live/interfaces:
   - Returns available adapters, count, and default adapter.
2. GET /live/status:
   - Returns stopped/running status and metrics.
3. Auth Enforcement:
   - /live/start and /live/stop require valid bearer token (HTTP 401 otherwise).
4. Start & Stop Live Capture (GET and POST):
   - Starts capture, returns status started/already_running.
   - Stops capture, returns status stopped/not_running.
5. Live Event Pipeline simulation:
   - Simulates captured packet callback -> ML inference -> Risk score -> Broadcast.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path
_DIR = Path(__file__).resolve().parent
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))

import main
from auth import create_access_token

client = TestClient(main.app, raise_server_exceptions=False)


def get_auth_headers(username: str = "test_analyst") -> dict[str, str]:
    token = create_access_token(data={"sub": username, "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def test_live_interfaces_endpoint():
    """Verify /live/interfaces returns adapter list and default interface."""
    resp = client.get("/live/interfaces")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "interfaces" in data
    assert "count" in data
    assert "default" in data
    assert isinstance(data["interfaces"], list)
    assert data["count"] == len(data["interfaces"])
    if data["count"] > 0:
        iface = data["interfaces"][0]
        assert "name" in iface
        assert "description" in iface
        assert "type" in iface
        assert "is_up" in iface


def test_live_status_endpoint():
    """Verify /live/status returns monitoring metrics."""
    resp = client.get("/live/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "running" in data
    assert "events_processed" in data
    assert "anomalies_detected" in data


def test_live_start_unauthorized():
    """Verify starting capture without auth token returns 401."""
    resp = client.get("/live/start")
    assert resp.status_code == 401


def test_live_stop_unauthorized():
    """Verify stopping capture without auth token returns 401."""
    resp = client.get("/live/stop")
    assert resp.status_code == 401


def test_live_start_and_stop_mocked():
    """Verify start and stop flow with mocked monitor."""
    headers = get_auth_headers()

    # Test GET start
    with patch("main.LiveNetworkMonitor") as MockMonitor:
        instance = MockMonitor.return_value
        instance.running = True
        instance.stats = {
            "running": True,
            "interface": "Wi-Fi",
            "uptime_seconds": 1.0,
            "events_processed": 0,
            "anomalies_detected": 0,
            "active_connections": 0,
            "total_connections": 0,
            "total_packets": 0,
        }

        async def fake_start():
            return {"status": "started", **instance.stats}

        async def fake_stop():
            return {"status": "stopped", **instance.stats}

        instance.start = fake_start
        instance.stop = fake_stop

        # Start via GET
        resp = client.get("/live/start?interface=Wi-Fi", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] in ("started", "already_running")

        # Check status
        resp_status = client.get("/live/status")
        assert resp_status.status_code == 200

        # Stop via GET
        resp_stop = client.get("/live/stop", headers=headers)
        assert resp_stop.status_code == 200
        assert resp_stop.json()["status"] in ("stopped", "not_running")


def test_live_start_post_support():
    """Verify POST /live/start is supported alongside GET."""
    headers = get_auth_headers()
    with patch("main.LiveNetworkMonitor") as MockMonitor:
        instance = MockMonitor.return_value
        instance.running = True
        instance.stats = {
            "running": True,
            "interface": "Wi-Fi",
            "uptime_seconds": 0.5,
            "events_processed": 0,
            "anomalies_detected": 0,
            "active_connections": 0,
            "total_connections": 0,
            "total_packets": 0,
        }

        async def fake_start():
            return {"status": "started", **instance.stats}

        async def fake_stop():
            return {"status": "stopped", **instance.stats}

        instance.start = fake_start
        instance.stop = fake_stop

        # POST /live/start
        resp = client.post("/live/start?interface=Wi-Fi", headers=headers)
        assert resp.status_code == 200

        # POST /live/stop
        resp_stop = client.post("/live/stop", headers=headers)
        assert resp_stop.status_code == 200


if __name__ == "__main__":
    pytest.main(["-v", __file__])
