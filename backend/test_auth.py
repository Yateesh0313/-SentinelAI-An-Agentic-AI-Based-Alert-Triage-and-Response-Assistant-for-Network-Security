"""Checkpoint A verification: JWT auth register/login/protect flow."""
import json
import sys
import httpx

BASE = "http://127.0.0.1:8000"
SEP = "-" * 55


def check(label: str, resp: httpx.Response, expect_status: int) -> dict:
    ok = resp.status_code == expect_status
    mark = "PASS" if ok else "FAIL"
    print(f"{mark} [{resp.status_code}] {label}")
    if not ok:
        print(f"  Expected {expect_status}, body: {resp.text[:300]}")
        sys.exit(1)
    try:
        return resp.json()
    except Exception:
        return {}


def run():
    print(SEP)
    print("  Checkpoint A — JWT Auth Verification")
    print(SEP)

    client = httpx.Client(timeout=15)

    # 1. Register
    print("\n1. Register new user")
    data = check("POST /auth/register", client.post(
        f"{BASE}/auth/register",
        json={"username": "analyst1", "password": "test123"},
    ), 201)
    print(f"   → username={data.get('username')} role={data.get('role')}")

    # 2. Duplicate register → 409
    print("\n2. Register duplicate → expect 409")
    check("POST /auth/register (duplicate)", client.post(
        f"{BASE}/auth/register",
        json={"username": "analyst1", "password": "anything"},
    ), 409)
    print("   → 409 Conflict confirmed")

    # 3. Login with wrong password → 401
    print("\n3. Login wrong password → expect 401")
    check("POST /auth/login (bad pw)", client.post(
        f"{BASE}/auth/login",
        json={"username": "analyst1", "password": "wrongpassword"},
    ), 401)
    print("   → 401 Unauthorized confirmed")

    # 4. Login correct → token
    print("\n4. Login correct credentials → JWT")
    token_data = check("POST /auth/login", client.post(
        f"{BASE}/auth/login",
        json={"username": "analyst1", "password": "test123"},
    ), 200)
    token = token_data.get("access_token", "")
    print(f"   → token_type={token_data.get('token_type')} username={token_data.get('username')}")
    print(f"   → token[:40]={token[:40]}...")

    # 5. Get a pending event ID to test approve/reject
    print("\n5. Fetch a pending event ID")
    events_data = client.get(f"{BASE}/events/pending").json()
    events = events_data.get("events", [])
    if not events:
        print("   No pending events — skip approve/reject test")
        event_id = None
    else:
        event_id = events[0]["event_id"]
        print(f"   → Using event_id={event_id}")

    # 6. Approve WITHOUT token → 401
    if event_id:
        print("\n6. Approve without token → expect 401")
        check("POST /events/{id}/approve (no token)", client.post(
            f"{BASE}/events/{event_id}/approve",
        ), 401)
        print("   → 401 Unauthorized confirmed")

    # 7. Approve WITH token → 200
    if event_id:
        print("\n7. Approve WITH token → expect 200")
        data = check("POST /events/{id}/approve (with token)", client.post(
            f"{BASE}/events/{event_id}/approve",
            headers={"Authorization": f"Bearer {token}"},
        ), 200)
        print(f"   → status={data.get('status')} resolved_by={data.get('resolved_by')}")

    # 8. Replay start WITHOUT token → 401
    print("\n8. Replay start without token → expect 401")
    check("GET /replay/start (no token)", client.get(f"{BASE}/replay/start"), 401)
    print("   → 401 Unauthorized confirmed")

    print("\n" + SEP)
    print("  ALL CHECKS PASSED — Checkpoint A complete!")
    print(SEP)


if __name__ == "__main__":
    run()
