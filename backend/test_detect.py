"""Test the /detect endpoint against real KDDTest+ rows.

Reads 10 real rows from KDDTest+ (raw, unprocessed), sends each as a
POST to http://localhost:8000/detect, and prints the prediction alongside
the actual ground-truth label so you can visually confirm predictions
look reasonable.

Usage:
    1. Start the backend:  uvicorn main:app --reload
    2. In another terminal: python test_detect.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import requests

# Add ml/data to path so we can import the loader
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "ml" / "data"))

from loader import load_arff  # noqa: E402

API_URL = "http://localhost:8000/detect"
N_SAMPLES = 10

# Feature columns (excluding 'class')
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


def main() -> None:
    """Load test rows and POST each to /detect."""
    print("=" * 72)
    print("  SentinelAI -- /detect Endpoint Test (real KDDTest+ rows)")
    print("=" * 72)
    print()

    # Load raw test data
    test_path = _PROJECT_ROOT / "ml" / "data" / "raw" / "nsl_kdd" / "KDDTest+.arff"
    print(f"  Loading raw data from {test_path.name} ...")
    df = load_arff(test_path)
    print(f"  Loaded {len(df)} rows, selecting first {N_SAMPLES}")
    print()

    # Pick a mix: first 5 + 5 from later in the file (more variety)
    indices = list(range(5)) + list(range(100, 105))
    correct = 0
    total = 0

    print(f"  {'#':<4} {'Actual':<10} {'Predicted':<10} {'Conf':>6} {'Match':>6}  "
          f"{'Proto':<6} {'Service':<12} {'Flag':<6}")
    print(f"  {'-'*4} {'-'*10} {'-'*10} {'-'*6} {'-'*6}  {'-'*6} {'-'*12} {'-'*6}")

    for i, idx in enumerate(indices):
        row = df.iloc[idx]
        actual = row["class"]

        # Build request payload
        payload: dict = {}
        for col in FEATURE_COLS:
            val = row[col]
            if col in CATEGORICAL_COLS:
                payload[col] = str(val)
            else:
                payload[col] = float(val)

        try:
            resp = requests.post(API_URL, json=payload, timeout=10)
            resp.raise_for_status()
            result = resp.json()
            predicted = result["prediction"]
            confidence = result["confidence"]
            match = "OK" if predicted == actual else "MISS"
            if predicted == actual:
                correct += 1
            total += 1

            print(f"  {i+1:<4} {actual:<10} {predicted:<10} {confidence:>6.2f} "
                  f"{match:>6}  {row['protocol_type']:<6} "
                  f"{row['service']:<12} {row['flag']:<6}")

        except requests.ConnectionError:
            print(f"  {i+1:<4} CONNECTION ERROR -- is the backend running on port 8000?")
            sys.exit(1)
        except Exception as exc:
            print(f"  {i+1:<4} ERROR: {exc}")

    print()
    print(f"  Accuracy on {total} samples: {correct}/{total} "
          f"({correct/total*100:.0f}%)")
    print()

    if correct / total < 0.3:
        print("  [WARNING] Very low accuracy -- predictions may be broken.")
        print("  Check that scaler/encoder match the training pipeline.")
    elif correct / total > 0.9:
        print("  [NOTE] Very high accuracy on this small sample -- expected")
        print("  to see some misses on KDDTest+ due to unseen attack types.")
    else:
        print("  [OK] Predictions look reasonable for KDDTest+ data.")

    print("=" * 72)


if __name__ == "__main__":
    main()
