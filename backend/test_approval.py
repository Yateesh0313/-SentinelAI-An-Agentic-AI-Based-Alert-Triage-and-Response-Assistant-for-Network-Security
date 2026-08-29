"""Test Phase 9 approval endpoints.

1. Sends 2 known-anomaly rows through /triage to get event_ids
2. Approves the first event
3. Rejects the second event
4. Tries to double-approve the first event (expects 409)
5. Checks /events/pending shows 0 remaining

Usage:
    1. Start backend: python -m uvicorn main:app --host 127.0.0.1 --port 8000
    2. Run this:      python test_approval.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import requests

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "ml" / "data"))
from loader import load_arff  # noqa: E402

API_BASE = "http://localhost:8000"

FEATURE_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
CATEGORICAL_COLS = {"protocol_type", "service", "flag"}


def build_payload(row):
    payload = {}
    for col in FEATURE_COLS:
        val = row[col]
        payload[col] = str(val) if col in CATEGORICAL_COLS else float(val)
    return payload


def main():
    print("=" * 72)
    print("  SentinelAI -- Phase 9 Approval Endpoint Test")
    print("=" * 72)
    print()

    # Load anomaly rows
    test_path = _PROJECT_ROOT / "ml" / "data" / "raw" / "nsl_kdd" / "KDDTest+.arff"
    df = load_arff(test_path)
    anomalies = df[df["class"] == "anomaly"].head(2)
    print(f"  Using {len(anomalies)} anomaly rows for testing")
    print()

    event_ids = []

    # Step 1: Send through /triage to get event_ids
    print("--- Step 1: Send 2 anomalies through /triage ---")
    for i, (_, row) in enumerate(anomalies.iterrows()):
        payload = build_payload(row)
        resp = requests.post(f"{API_BASE}/triage", json=payload, timeout=30)
        result = resp.json()
        eid = result.get("event_id")
        status = result.get("status")
        severity = result.get("severity")
        action = result.get("recommended_action")
        print(f"  Event {i+1}: id={eid}, status={status}, "
              f"severity={severity}, action={action}")
        if eid:
            event_ids.append(eid)
    print()

    if len(event_ids) < 2:
        print("  [ERROR] Didn't get 2 event_ids. Aborting.")
        return

    # Step 2: Check pending
    print("--- Step 2: Check /events/pending ---")
    resp = requests.get(f"{API_BASE}/events/pending")
    pending = resp.json()
    print(f"  Pending count: {pending['count']}")
    print()

    # Step 3: Approve first event
    print(f"--- Step 3: Approve event {event_ids[0]} ---")
    resp = requests.post(f"{API_BASE}/events/{event_ids[0]}/approve")
    print(f"  Status: {resp.status_code}")
    print(f"  Response: {resp.json()}")
    print()

    # Step 4: Reject second event
    print(f"--- Step 4: Reject event {event_ids[1]} ---")
    resp = requests.post(f"{API_BASE}/events/{event_ids[1]}/reject")
    print(f"  Status: {resp.status_code}")
    print(f"  Response: {resp.json()}")
    print()

    # Step 5: Double-approve first event (should get 409)
    print(f"--- Step 5: Double-approve event {event_ids[0]} (expect 409) ---")
    resp = requests.post(f"{API_BASE}/events/{event_ids[0]}/approve")
    print(f"  Status: {resp.status_code} (expected: 409)")
    print(f"  Response: {resp.json()}")
    passed = resp.status_code == 409
    print(f"  409 guard: {'PASS' if passed else 'FAIL'}")
    print()

    # Step 6: Double-reject second event (should get 409)
    print(f"--- Step 6: Double-reject event {event_ids[1]} (expect 409) ---")
    resp = requests.post(f"{API_BASE}/events/{event_ids[1]}/reject")
    print(f"  Status: {resp.status_code} (expected: 409)")
    passed2 = resp.status_code == 409
    print(f"  409 guard: {'PASS' if passed2 else 'FAIL'}")
    print()

    # Step 7: Check pending again (should be 0)
    print("--- Step 7: Check /events/pending (should be 0) ---")
    resp = requests.get(f"{API_BASE}/events/pending")
    pending = resp.json()
    print(f"  Pending count: {pending['count']} (expected: 0)")
    print()

    # Step 8: Check individual event status
    print(f"--- Step 8: Check /events/{event_ids[0]} ---")
    resp = requests.get(f"{API_BASE}/events/{event_ids[0]}")
    print(f"  Status: {resp.json().get('status')} (expected: approved)")
    print()

    print("=" * 72)
    all_passed = passed and passed2 and pending["count"] == 0
    print(f"  Overall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 72)


if __name__ == "__main__":
    main()
