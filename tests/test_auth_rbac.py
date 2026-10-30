"""SentinelAI — RBAC & Auth Enforcement Tests.

Tests that every protected endpoint:
  1. Returns 401 when called without a JWT token.
  2. Returns 403 when called with an insufficient role (where applicable).
  3. Returns 200/2xx when called with the correct role.

Run:
    cd backend
    python -m pytest ../tests/test_auth_rbac.py -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure backend/ is importable
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"
_AGENTS_DIR = Path(__file__).resolve().parent.parent / "agents"
_ML_DIR = Path(__file__).resolve().parent.parent / "ml"
for p in [str(_BACKEND_DIR), str(_AGENTS_DIR), str(_ML_DIR),
          str(_ML_DIR / "live_capture"), str(_ML_DIR / "signatures"),
          str(_ML_DIR / "honeypot")]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Set env vars BEFORE importing any backend code
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-rbac-tests-only-64chars-min-abcdef1234567890")
os.environ.setdefault("RESEARCH_MODE", "false")

from auth import create_access_token

# ---------------------------------------------------------------------------
# FastAPI test client
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a TestClient for the SentinelAI FastAPI app."""
    from main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------

def _make_token(role: str = "analyst", username: str = "testuser") -> str:
    return create_access_token({"sub": username, "role": role})


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Route definitions with expected auth levels
# ---------------------------------------------------------------------------

# (method, path, minimum_role)
# minimum_role = None means "any authenticated user" (get_current_user)
# minimum_role = "analyst" means require_role("analyst")
# minimum_role = "admin" means require_role("admin")

PUBLIC_ROUTES = [
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/config/mode"),
]

AUTHENTICATED_ROUTES = [
    # (method, path) — any logged-in user should get through
    ("GET", "/events/pending"),
    ("GET", "/events/history"),
    ("GET", "/events/filter"),
    ("GET", "/stats/overview"),
    ("GET", "/honeypot/status"),
    ("GET", "/suricata/status"),
    ("GET", "/live/status"),
    ("GET", "/interfaces"),
    ("GET", "/live/interfaces"),
]

ANALYST_ROUTES = [
    # These need at least "analyst" role
    ("POST", "/replay/start"),
    ("POST", "/replay/stop"),
]

ADMIN_ROUTES = [
    # These need "admin" role
    ("GET", "/logs/csv/list"),
]


# ===========================================================================
# Test 1: Public routes work without any token
# ===========================================================================

@pytest.mark.parametrize("method,path", PUBLIC_ROUTES)
def test_public_routes_no_token(client, method, path):
    """Public routes should return 2xx without authentication."""
    resp = client.request(method, path)
    assert resp.status_code < 400, (
        f"{method} {path} returned {resp.status_code} — expected public access"
    )


# ===========================================================================
# Test 2: Authenticated routes return 401 without token
# ===========================================================================

@pytest.mark.parametrize("method,path", AUTHENTICATED_ROUTES + ANALYST_ROUTES + ADMIN_ROUTES)
def test_authenticated_routes_require_token(client, method, path):
    """Protected routes must return 401 when no token is provided."""
    resp = client.request(method, path)
    assert resp.status_code == 401, (
        f"{method} {path} returned {resp.status_code} — expected 401 Unauthorized"
    )


# ===========================================================================
# Test 3: Analyst-only routes return 403 for viewer role
# ===========================================================================

@pytest.mark.parametrize("method,path", ANALYST_ROUTES)
def test_analyst_routes_reject_viewer(client, method, path):
    """Analyst-level routes must return 403 for a viewer-role token."""
    token = _make_token(role="viewer")
    resp = client.request(method, path, headers=_auth(token))
    assert resp.status_code == 403, (
        f"{method} {path} returned {resp.status_code} for viewer — expected 403 Forbidden"
    )


# ===========================================================================
# Test 4: Admin-only routes return 403 for analyst role
# ===========================================================================

@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_reject_analyst(client, method, path):
    """Admin-level routes must return 403 for an analyst-role token."""
    token = _make_token(role="analyst")
    resp = client.request(method, path, headers=_auth(token))
    assert resp.status_code == 403, (
        f"{method} {path} returned {resp.status_code} for analyst — expected 403 Forbidden"
    )


# ===========================================================================
# Test 5: Admin-only routes return 403 for viewer role
# ===========================================================================

@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_reject_viewer(client, method, path):
    """Admin-level routes must return 403 for a viewer-role token."""
    token = _make_token(role="viewer")
    resp = client.request(method, path, headers=_auth(token))
    assert resp.status_code == 403, (
        f"{method} {path} returned {resp.status_code} for viewer — expected 403 Forbidden"
    )


# ===========================================================================
# Test 6: Authenticated routes accept any valid token
# ===========================================================================

@pytest.mark.parametrize("method,path", AUTHENTICATED_ROUTES)
def test_authenticated_routes_accept_valid_token(client, method, path):
    """Authenticated routes should not return 401/403 with a valid token."""
    token = _make_token(role="viewer")
    resp = client.request(method, path, headers=_auth(token))
    # May return 500 (DB not connected) but NOT 401 or 403
    assert resp.status_code not in (401, 403), (
        f"{method} {path} returned {resp.status_code} for valid token — "
        "expected auth to pass (non-401/403)"
    )


# ===========================================================================
# Test 7: Analyst routes accept analyst token
# ===========================================================================

@pytest.mark.parametrize("method,path", ANALYST_ROUTES)
def test_analyst_routes_accept_analyst_token(client, method, path):
    """Analyst-level routes should not return 401/403 with analyst token."""
    token = _make_token(role="analyst")
    resp = client.request(method, path, headers=_auth(token))
    assert resp.status_code not in (401, 403), (
        f"{method} {path} returned {resp.status_code} for analyst — "
        "expected auth to pass"
    )


# ===========================================================================
# Test 8: Admin routes accept admin token
# ===========================================================================

@pytest.mark.parametrize("method,path", ADMIN_ROUTES)
def test_admin_routes_accept_admin_token(client, method, path):
    """Admin-level routes should not return 401/403 with admin token."""
    token = _make_token(role="admin")
    resp = client.request(method, path, headers=_auth(token))
    assert resp.status_code not in (401, 403), (
        f"{method} {path} returned {resp.status_code} for admin — "
        "expected auth to pass"
    )


# ===========================================================================
# Test 9: POST endpoints with body — auth check
# ===========================================================================

def test_detect_requires_auth(client):
    """POST /detect must require authentication."""
    resp = client.post("/detect", json={"duration": 0})
    assert resp.status_code == 401

def test_triage_requires_auth(client):
    """POST /triage must require authentication."""
    resp = client.post("/triage", json={"duration": 0})
    assert resp.status_code == 401

def test_dataset_upload_requires_auth(client):
    """POST /dataset/upload must require authentication."""
    resp = client.post("/dataset/upload", files={"file": ("test.csv", b"a,b\n1,2")})
    assert resp.status_code == 401

def test_dataset_upload_requires_analyst(client):
    """POST /dataset/upload must reject viewer role."""
    token = _make_token(role="viewer")
    resp = client.post(
        "/dataset/upload",
        files={"file": ("test.csv", b"a,b\n1,2")},
        headers=_auth(token),
    )
    assert resp.status_code == 403


# ===========================================================================
# Test 10: Upload validation
# ===========================================================================

def test_upload_rejects_non_csv(client):
    """POST /dataset/upload must reject non-.csv files."""
    token = _make_token(role="analyst")
    resp = client.post(
        "/dataset/upload",
        files={"file": ("test.json", b'{"a": 1}', "application/json")},
        headers=_auth(token),
    )
    assert resp.status_code == 400
    assert "csv" in resp.json().get("detail", "").lower()

def test_upload_rejects_empty_file(client):
    """POST /dataset/upload must reject empty files."""
    token = _make_token(role="analyst")
    resp = client.post(
        "/dataset/upload",
        files={"file": ("empty.csv", b"", "text/csv")},
        headers=_auth(token),
    )
    assert resp.status_code == 400
    assert "empty" in resp.json().get("detail", "").lower()


# ===========================================================================
# Test 11: Approve/reject require analyst role
# ===========================================================================

def test_approve_requires_auth(client):
    """POST /events/{id}/approve must require authentication."""
    resp = client.post("/events/fake-id/approve")
    assert resp.status_code == 401

def test_approve_requires_analyst(client):
    """POST /events/{id}/approve must reject viewer role."""
    token = _make_token(role="viewer")
    resp = client.post("/events/fake-id/approve", headers=_auth(token))
    assert resp.status_code == 403

def test_reject_requires_auth(client):
    """POST /events/{id}/reject must require authentication."""
    resp = client.post("/events/fake-id/reject")
    assert resp.status_code == 401

def test_reject_requires_analyst(client):
    """POST /events/{id}/reject must reject viewer role."""
    token = _make_token(role="viewer")
    resp = client.post("/events/fake-id/reject", headers=_auth(token))
    assert resp.status_code == 403


# ===========================================================================
# Test 12: CSV export requires admin
# ===========================================================================

def test_csv_export_requires_auth(client):
    """GET /logs/export/csv/suricata must require authentication."""
    resp = client.get("/logs/export/csv/suricata")
    assert resp.status_code == 401

def test_csv_export_requires_admin(client):
    """GET /logs/export/csv/suricata must reject analyst role."""
    token = _make_token(role="analyst")
    resp = client.get("/logs/export/csv/suricata", headers=_auth(token))
    assert resp.status_code == 403


# ===========================================================================
# Test 13: WebSocket requires token
# ===========================================================================

def test_websocket_rejects_no_token(client):
    """WS /ws must reject connections without a token query param."""
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws") as ws:
            ws.receive_text()  # should not reach here


def test_websocket_rejects_invalid_token(client):
    """WS /ws must reject connections with an invalid token."""
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?token=invalid-garbage-token") as ws:
            ws.receive_text()  # should not reach here


# ===========================================================================
# Test 14: Expired/malformed tokens return 401
# ===========================================================================

def test_expired_token_returns_401(client):
    """An expired JWT should return 401."""
    from jose import jwt as jose_jwt
    from datetime import datetime, timedelta, timezone
    expired_token = jose_jwt.encode(
        {"sub": "testuser", "role": "analyst",
         "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
        os.environ["JWT_SECRET"],
        algorithm="HS256",
    )
    resp = client.get("/events/pending", headers=_auth(expired_token))
    assert resp.status_code == 401
