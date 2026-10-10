"""SentinelAI — Phase 14 Integration Test.

1. Captures live packets from loopback using Scapy
2. Generates a synthetic Zeek conn.log from the capture
3. Parses it back through the Zeek parser
4. Runs each parsed event through the /detect pipeline
"""

import sys
import json
from pathlib import Path

# Setup paths
root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(root / "ml" / "live_capture"))
sys.path.insert(0, str(root / "ml" / "signatures"))
sys.path.insert(0, str(root / "backend"))

from scapy_capture import capture_packets
from zeek_parser_archived import parse_conn_log_to_events

# Step 1: Capture packets (loopback, bounded)
print("=" * 60)
print("STEP 1: Live packet capture (Scapy)")
print("=" * 60)

output_dir = root / "ml" / "live_capture" / "captures"
events = capture_packets(
    interface=None,  # Default interface
    max_packets=30,
    timeout=10,
    output_dir=output_dir,
)

if not events:
    print("\nNo packets captured. This is expected if:")
    print("  - Not running as administrator (needed for raw sockets)")
    print("  - No network traffic during the capture window")
    print("\nGenerating a synthetic conn.log for Zeek parser testing...")

    # Generate a minimal synthetic conn.log for testing
    import time
    conn_log_path = output_dir / "conn.log"
    output_dir.mkdir(parents=True, exist_ok=True)

    with open(conn_log_path, "w") as f:
        f.write("#separator \\x09\n")
        f.write("#set_separator\t,\n")
        f.write("#empty_field\t(empty)\n")
        f.write("#unset_field\t-\n")
        f.write("#path\tconn\n")
        f.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
                "proto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\t"
                "local_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\t"
                "orig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n")
        f.write("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\t"
                "interval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\t"
                "count\tcount\tcount\tcount\tset[string]\n")

        # Sample connections representing real-world traffic patterns
        samples = [
            # Normal HTTP browsing
            (f"{time.time()}", "Cabc123def456", "192.168.1.100", "49152",
             "93.184.216.34", "80", "tcp", "http", "0.45",
             "350", "12500", "SF"),
            # DNS lookup
            (f"{time.time()}", "Cdef789abc012", "192.168.1.100", "53214",
             "8.8.8.8", "53", "udp", "dns", "0.02",
             "64", "128", "SF"),
            # SSH connection
            (f"{time.time()}", "C345678901234", "192.168.1.100", "54321",
             "10.0.0.5", "22", "tcp", "ssh", "120.5",
             "5200", "3800", "SF"),
            # Failed connection (SYN, no response)
            (f"{time.time()}", "C567890123456", "192.168.1.100", "49200",
             "10.0.0.99", "8080", "tcp", "-", "0.0",
             "0", "0", "S0"),
            # HTTPS traffic
            (f"{time.time()}", "C789012345678", "192.168.1.100", "51234",
             "142.250.80.46", "443", "tcp", "ssl", "2.1",
             "1800", "45000", "SF"),
        ]

        for s in samples:
            row = list(s) + ["-", "-", "0", "-", "0", "0", "0", "0", "-"]
            f.write("\t".join(row) + "\n")

    print(f"  Created synthetic conn.log with {len(samples)} sample connections")

# Step 2: Parse with Zeek parser
print()
print("=" * 60)
print("STEP 2: Parse conn.log with Zeek parser")
print("=" * 60)

conn_log_path = output_dir / "conn.log"
zeek_events = parse_conn_log_to_events(conn_log_path)

for i, evt in enumerate(zeek_events):
    meta = evt.get("_meta", {})
    print(f"\n  Connection {i+1}:")
    print(f"    {meta.get('src_ip', '?')}:{meta.get('src_port', '?')} -> "
          f"{meta.get('dst_ip', '?')}:{meta.get('dst_port', '?')}")
    print(f"    proto={evt['protocol_type']} service={evt['service']} "
          f"flag={evt['flag']} duration={evt['duration']}")
    print(f"    src_bytes={evt['src_bytes']} dst_bytes={evt['dst_bytes']}")
    print(f"    source={meta.get('source', '?')} zeek_service={meta.get('zeek_service', '?')}")

# Step 3: Run through ML detection
print()
print("=" * 60)
print("STEP 3: Run parsed events through /detect pipeline")
print("=" * 60)

import joblib
import numpy as np
import pandas as pd

# Load ML artifacts
model = joblib.load(root / "ml" / "results" / "classical_baseline_model.joblib")
scaler = joblib.load(root / "ml" / "data" / "processed" / "scaler.joblib")
encoder = joblib.load(root / "ml" / "data" / "processed" / "encoder.joblib")

from matcher import match_signatures

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
CAT_COLS = ["protocol_type", "service", "flag"]
NUM_COLS = [c for c in FEATURE_COLS if c not in CAT_COLS]

import warnings
warnings.filterwarnings("ignore")

for i, evt in enumerate(zeek_events):
    meta = evt.pop("_meta", {})

    # Ensure proper types
    for col in CAT_COLS:
        evt[col] = str(evt[col])
    for col in NUM_COLS:
        evt[col] = float(evt[col])

    # ML prediction
    try:
        df = pd.DataFrame([evt])
        cat_encoded = encoder.transform(df[CAT_COLS])
        cat_df = pd.DataFrame(cat_encoded, columns=encoder.get_feature_names_out(CAT_COLS))
        num_df = df[NUM_COLS].copy()
        num_scaled = pd.DataFrame(scaler.transform(num_df), columns=NUM_COLS)
        X = pd.concat([num_scaled, cat_df], axis=1)
        prob = model.predict_proba(X)[0]
        pred_idx = int(np.argmax(prob))
        label = model.classes_[pred_idx]
        confidence = float(prob[pred_idx])
    except Exception as exc:
        label = "error"
        confidence = 0.0
        print(f"  ML error for event {i+1}: {exc}")

    # Signature matching
    sigs = match_signatures(evt)
    sig_names = [s["rule"] for s in sigs]

    src = meta.get("src_ip", "?")
    dst = meta.get("dst_ip", "?")
    svc = evt["service"]

    print(f"\n  Event {i+1}: {src} -> {dst} ({svc})")
    print(f"    ML:         {label} ({confidence:.1%})")
    print(f"    Signatures: {sig_names if sig_names else 'none'}")
    print(f"    Flagged:    {'YES' if (label == 'anomaly' or sigs) else 'no'}")

print()
print("=" * 60)
print("Phase 14 integration test complete!")
print("=" * 60)
