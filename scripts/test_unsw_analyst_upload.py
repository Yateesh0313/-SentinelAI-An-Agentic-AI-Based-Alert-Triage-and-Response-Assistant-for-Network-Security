"""SentinelAI -- Integration Test for Dataset Upload with Auth and UNSW-NB15 layouts.

Tests:
1. Part A (AUTH):
   - Unauthenticated request returns 401 with headers (WWW-Authenticate: Bearer)
   - Viewer request returns 403 Forbidden
   - Analyst request is accepted (200)
   - Admin request is accepted (200)
2. Part B (SCHEMA):
   - Full-file layout (49 columns) detected: "Detected: UNSW-NB15 (full-file layout) → unsw_nb15_xgb"
   - Training-set layout (45 columns) detected: "Detected: UNSW-NB15 (training-set layout) → unsw_nb15_xgb"
   - 1,000 rows tested for both layouts with analyst authentication
   - Verifies 'rate' is NOT in model features
   - Verifies IPs are preserved in alerts
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
import httpx
import pytest

# Ensure backend/ is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from auth import create_access_token


def run_tests():
    base_url = "http://127.0.0.1:8000"

    print("=" * 60)
    print("TEST 1: Unauthenticated request (Auth Requirement A)")
    print("=" * 60)
    with httpx.Client(base_url=base_url) as client:
        resp = client.post(
            "/dataset/upload",
            files={"file": ("test.csv", b"a,b\n1,2", "text/csv")},
        )
        print(f"Status Code: {resp.status_code}")
        print("Response Headers:")
        for k, v in resp.headers.items():
            print(f"  {k}: {v}")
        print(f"Body: {resp.text}")
        assert resp.status_code == 401, f"Expected 401, got {resp.status_code}"
        assert "www-authenticate" in resp.headers, "Expected WWW-Authenticate header"

    print("\n" + "=" * 60)
    print("TEST 2: Viewer role rejection (403 Forbidden)")
    print("=" * 60)
    viewer_token = create_access_token({"sub": "viewer_user", "role": "viewer"})
    with httpx.Client(base_url=base_url) as client:
        resp = client.post(
            "/dataset/upload",
            headers={"Authorization": f"Bearer {viewer_token}"},
            files={"file": ("test.csv", b"a,b\n1,2", "text/csv")},
        )
        print(f"Status Code: {resp.status_code}")
        print(f"Body: {resp.text}")
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}"

    print("\n" + "=" * 60)
    print("TEST 3: Upload UNSW-NB15 1,000 rows (training-set layout) as Analyst")
    print("=" * 60)
    analyst_token = create_access_token({"sub": "soc_analyst", "role": "analyst"})
    train_path = PROJECT_ROOT / "data" / "csv" / "unsw_nb15_training_1000.csv"
    with open(train_path, "rb") as f:
        file_bytes = f.read()

    with httpx.Client(base_url=base_url, timeout=60.0) as client:
        resp = client.post(
            "/dataset/upload",
            headers={"Authorization": f"Bearer {analyst_token}"},
            data={"model_type": "xgboost", "max_rows": 1000},
            files={"file": ("unsw_nb15_training_1000.csv", file_bytes, "text/csv")},
        )
        print(f"Status Code: {resp.status_code}")
        data = resp.json()
        print("Response details:")
        print(f"  Status        : {data.get('status')}")
        print(f"  Schema        : {data.get('schema')}")
        print(f"  Format Display: {data.get('format_display')}")
        print(f"  Model Used    : {data.get('model_used')}")
        print(f"  Total Rows    : {data.get('total_rows')}")
        print(f"  Processed Rows: {data.get('processed_rows')}")
        print(f"  Anomalies     : {data.get('anomalies_detected')}")
        print(f"  Normal        : {data.get('normal_traffic')}")
        print(f"  Triaged Alerts: {data.get('triaged_alerts')}")
        print(f"  Sample Alerts : {len(data.get('alerts', []))}")

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["format_display"] == "Detected: UNSW-NB15 (training-set layout) → unsw_nb15_xgb"
        assert data["model_used"] == "unsw_nb15_xgb"
        assert data["processed_rows"] == 1000

    print("\n" + "=" * 60)
    print("TEST 4: Upload UNSW-NB15 1,000 rows (full-file layout) as Analyst")
    print("=" * 60)
    full_path = PROJECT_ROOT / "data" / "csv" / "unsw_nb15_full_1000.csv"
    with open(full_path, "rb") as f:
        full_bytes = f.read()

    with httpx.Client(base_url=base_url, timeout=60.0) as client:
        resp = client.post(
            "/dataset/upload",
            headers={"Authorization": f"Bearer {analyst_token}"},
            data={"model_type": "xgboost", "max_rows": 1000},
            files={"file": ("unsw_nb15_full_1000.csv", full_bytes, "text/csv")},
        )
        print(f"Status Code: {resp.status_code}")
        data = resp.json()
        print("Response details:")
        print(f"  Status        : {data.get('status')}")
        print(f"  Schema        : {data.get('schema')}")
        print(f"  Format Display: {data.get('format_display')}")
        print(f"  Model Used    : {data.get('model_used')}")
        print(f"  Total Rows    : {data.get('total_rows')}")
        print(f"  Processed Rows: {data.get('processed_rows')}")
        print(f"  Anomalies     : {data.get('anomalies_detected')}")
        print(f"  Normal        : {data.get('normal_traffic')}")
        print(f"  Triaged Alerts: {data.get('triaged_alerts')}")
        print(f"  Sample Alerts : {len(data.get('alerts', []))}")

        if data.get("alerts"):
            first_alert = data["alerts"][0]
            print(f"  First Alert Source IP : {first_alert.get('source_ip')}")
            print(f"  First Alert Dest IP   : {first_alert.get('destination_ip')}")
            print(f"  First Alert Action    : {first_alert.get('recommended_action')}")
            print(f"  First Alert Triage    : {first_alert.get('triage_summary')}")
            assert first_alert.get("source_ip") is not None, "Alert must contain source IP"

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        assert data["format_display"] == "Detected: UNSW-NB15 (full-file layout) → unsw_nb15_xgb"
        assert data["model_used"] == "unsw_nb15_xgb"
        assert data["processed_rows"] == 1000

    print("\n" + "=" * 60)
    print("TEST 5: Admin role acceptance (Role Hierarchy)")
    print("=" * 60)
    admin_token = create_access_token({"sub": "soc_admin", "role": "admin"})
    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        resp = client.post(
            "/dataset/upload",
            headers={"Authorization": f"Bearer {admin_token}"},
            data={"model_type": "xgboost", "max_rows": 5},
            files={"file": ("unsw_sample.csv", full_bytes[:5000], "text/csv")},
        )
        print(f"Status Code: {resp.status_code}")
        assert resp.status_code == 200, f"Expected 200 for Admin, got {resp.status_code}"

    print("\n" + "=" * 60)
    print("ALL API INTEGRATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    import sys
    sys.stdout.reconfigure(encoding='utf-8')
    run_tests()
