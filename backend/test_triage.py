"""Test the /triage endpoint with known-anomaly KDDTest+ rows.

Sends a few KNOWN-anomaly rows through the full detect -> agent pipeline
and prints the complete chain output so you can verify:
  1. The detection correctly flags them as anomalies
  2. The LLM triage explanation references actual fields from the event
  3. Severity and recommended_action are from the allowed vocabularies
  4. Agent chain latency is reported

Usage:
    1. Start backend: python -m uvicorn main:app --host 127.0.0.1 --port 8000
    2. Run this:      python test_triage.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import requests

# Add ml/data to path for the loader
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "ml" / "data"))

from loader import load_arff  # noqa: E402

API_URL = "http://localhost:8000/triage"

# Feature columns
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
ALLOWED_SEVERITIES = {"Low", "Medium", "High", "Critical", "UNKNOWN"}
ALLOWED_ACTIONS = {"block_ip", "isolate_host", "flag_for_review", "no_action"}


def main() -> None:
    """Send known-anomaly rows through /triage and print full chain output."""
    print("=" * 72)
    print("  SentinelAI -- /triage Full Pipeline Test")
    print("=" * 72)
    print()

    # Load raw test data and find anomaly rows
    test_path = _PROJECT_ROOT / "ml" / "data" / "raw" / "nsl_kdd" / "KDDTest+.arff"
    print(f"  Loading raw data from {test_path.name} ...")
    df = load_arff(test_path)

    # Pick 3 known anomalies with different characteristics
    anomaly_rows = df[df["class"] == "anomaly"]
    # Pick diverse protocol_type values
    samples = []
    for proto in ["tcp", "icmp", "udp"]:
        subset = anomaly_rows[anomaly_rows["protocol_type"] == proto]
        if len(subset) > 0:
            samples.append(subset.iloc[0])
    # Add one normal event to verify it skips the agent pipeline
    normal_rows = df[df["class"] == "normal"]
    if len(normal_rows) > 0:
        samples.append(normal_rows.iloc[0])

    print(f"  Selected {len(samples)} test events "
          f"({len(samples)-1} anomalies + 1 normal)")
    print()

    for i, row in enumerate(samples):
        actual = row["class"]
        proto = row["protocol_type"]
        service = row["service"]
        flag = row["flag"]

        print(f"--- Event {i+1}/{len(samples)} ---")
        print(f"  Actual: {actual} | Proto: {proto} | "
              f"Service: {service} | Flag: {flag}")

        # Build payload
        payload: dict = {}
        for col in FEATURE_COLS:
            val = row[col]
            if col in CATEGORICAL_COLS:
                payload[col] = str(val)
            else:
                payload[col] = float(val)

        try:
            resp = requests.post(API_URL, json=payload, timeout=30)
            resp.raise_for_status()
            result = resp.json()
        except requests.ConnectionError:
            print("  CONNECTION ERROR -- is the backend running on port 8000?")
            sys.exit(1)
        except Exception as exc:
            print(f"  ERROR: {exc}")
            continue

        detection = result.get("detection", {})
        pred = detection.get("prediction", "?")
        conf = detection.get("confidence", 0)
        print(f"  Detection: {pred} (confidence: {conf:.2f})")

        triage_text = result.get("triage")
        severity = result.get("severity")
        justification = result.get("severity_justification")
        action = result.get("recommended_action")
        latency = result.get("agent_latency_seconds", 0)

        if triage_text is None:
            print("  Agent pipeline: SKIPPED (normal traffic)")
        else:
            print(f"  Triage: {triage_text}")
            print(f"  Severity: {severity}")
            print(f"  Justification: {justification}")
            print(f"  Action: {action}")
            print(f"  Agent latency: {latency}s")

            # Validate allowed values
            if severity not in ALLOWED_SEVERITIES:
                print(f"  [WARNING] Severity '{severity}' not in allowed set!")
            if action not in ALLOWED_ACTIONS:
                print(f"  [WARNING] Action '{action}' not in allowed set!")

        print()

    print("=" * 72)
    print("  Test complete. Review triage explanations above for:")
    print("  - Grounding: does the explanation reference actual event fields?")
    print("  - Hallucination: does it invent details not in the input?")
    print("  - Normal skip: was the agent pipeline skipped for the normal event?")
    print("=" * 72)


if __name__ == "__main__":
    main()
