"""SentinelAI — One-Command Judge Demo Seed Script (Phase 19).

Populates MongoDB with a curated, realistic dataset of ~28 network security events
from KDDTest+ so judges see an active, populated SOC dashboard instantly.

Covers:
  - Critical / High anomalies with clear ATT&CK & YARA rule matches
  - Medium anomalies & reconnaissance
  - Low / Normal legitimate traffic (demonstrating the system is not alarmist)
  - Pre-resolved events (approved, rejected, investigating, false positive) for the History tab
  - Staggered timestamps over the past hour

Usage:
  python scripts/seed_demo.py
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add project subdirectories to sys.path
_ROOT = Path(__file__).resolve().parent.parent
for d in ["backend", "agents", "ml/signatures", "ml/data"]:
    p = str(_ROOT / d)
    if p not in sys.path:
        sys.path.insert(0, p)

from dotenv import load_dotenv
load_dotenv(_ROOT / "backend" / ".env")
load_dotenv(_ROOT / "agents" / ".env")

import joblib
import numpy as np
import pandas as pd
from motor.motor_asyncio import AsyncIOMotorClient

import database as db
from enrichment import enrich_ip
from matcher import match_signatures
from attack_mapping import map_attack_techniques
from risk_scoring import calculate_risk_score
from loader import load_arff

# Curated diverse indices from KDDTest+.arff
CURATED_INDICES = [
    0,     # anomaly, private, REJ, T1095
    2,     # normal, ftp_data, SF
    5,     # normal, http, SF
    6,     # normal, smtp, SF
    13,    # anomaly, telnet, S0, T1498 (SYN flood), SYN_Flood_Pattern
    18,    # normal, private, SF
    21,    # anomaly, pop_3, S0, SYN_Flood_Pattern
    28,    # anomaly, ecr_i, SF, T1071, ICMP_Unusual_Bytes
    30,    # anomaly, http, RSTR, T1041 (Exfiltration)
    34,    # anomaly, private, REJ, T1046 (Port scan), Multi_Host_Recon
    35,    # anomaly, imap4, RSTO, Multi_Host_Recon
    61,    # anomaly, ftp_data, SF, T1041, Large_Outbound_Transfer
    82,    # anomaly, ecr_i, SF, ICMP_Unusual_Bytes
    100,   # anomaly, other, S0, T1046, Multi_Host_Recon, SYN_Flood
    152,   # anomaly, ecr_i, SF, ICMP_Unusual_Bytes
    233,   # normal, http, SF
    238,   # anomaly, http, RSTR, T1041, T1095
    345,   # anomaly, private, SF, T1046, Multi_Host_Recon
    347,   # anomaly, other, REJ, T1095
    384,   # anomaly, telnet, SF, T1068 (Privilege Escalation), Telnet_Root_Access
    438,   # normal, eco_i, SF
    476,   # normal, private, RSTR
    569,   # normal, private, SF
    599,   # anomaly, private, REJ, T1046
    672,   # normal, ftp_data, SF
    738,   # anomaly, ftp_data, SF, T1041, Large_Outbound_Transfer
    925,   # anomaly, telnet, SF, T1068, Telnet_Root_Access
    1166,  # anomaly, ftp_data, S0, T1498, FTP_Failed_Connection, SYN_Flood
]

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
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
NUMERIC_COLS = [c for c in FEATURE_COLS if c not in CATEGORICAL_COLS]


def fallback_triage(raw: dict, techniques: list[dict], sigs: list[dict]) -> dict:
    """Deterministic fallback triage if LLM API is rate-limited or unavailable."""
    tech_names = [t["name"] for t in techniques]
    sig_names = [s["rule"] for s in sigs]
    service = str(raw.get("service", "unknown"))

    if any(s.get("severity") == "critical" for s in sigs) or "Exploitation for Privilege Escalation" in tech_names:
        return {
            "triage": f"Critical security alert on service '{service}'. Root-level compromise or privilege escalation detected.",
            "severity": "Critical",
            "severity_justification": "Direct evidence of unauthorized administrative shell access or high-impact exploit.",
            "recommended_action": "isolate_host",
        }
    elif "Network Denial of Service" in tech_names or any(s.get("severity") == "high" for s in sigs):
        return {
            "triage": f"High volume DoS / SYN flood pattern detected targeting service '{service}'.",
            "severity": "High",
            "severity_justification": "Elevated connection failure rates and flood signatures indicate active resource exhaustion.",
            "recommended_action": "block_ip",
        }
    elif "Exfiltration Over C2 Channel" in tech_names or "Large_Outbound_Transfer" in sig_names:
        return {
            "triage": f"Abnormal outbound data transfer detected over service '{service}'.",
            "severity": "High",
            "severity_justification": "High source bytes ratio with minimal return traffic suggests data staging or exfiltration.",
            "recommended_action": "block_ip",
        }
    elif "Network Service Discovery" in tech_names or "Multi_Host_Reconnaissance" in sig_names:
        return {
            "triage": f"Reconnaissance and service probing activity observed against service '{service}'.",
            "severity": "Medium",
            "severity_justification": "Distinct destination port scanning behavior indicating pre-attack network mapping.",
            "recommended_action": "flag_for_review",
        }
    else:
        return {
            "triage": f"Anomalous traffic pattern detected on service '{service}'.",
            "severity": "Medium",
            "severity_justification": "Statistical deviations from baseline protocol behavior warrant analyst verification.",
            "recommended_action": "flag_for_review",
        }


def to_python_types(obj):
    """Recursively convert numpy types to native Python types for BSON serialization."""
    if isinstance(obj, dict):
        return {k: to_python_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [to_python_types(v) for v in obj]
    elif isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


async def seed_events():
    print("=" * 70)
    print("  SentinelAI — Demo Seed Initialization (Phase 19)")
    print("=" * 70)

    # 1. Connect to MongoDB
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    client = AsyncIOMotorClient(mongo_uri, serverSelectionTimeoutMS=5000)
    database = client[os.getenv("MONGO_DB_NAME", "sentinelai")]

    print(f"  Connected to MongoDB at {mongo_uri}")
    await database.events.delete_many({})
    print("  Cleaned previous events collection.")

    # 2. Load ML artifacts
    model = joblib.load(_ROOT / "ml" / "results" / "classical_baseline_model.joblib")
    scaler = joblib.load(_ROOT / "ml" / "data" / "processed" / "scaler.joblib")
    encoder = joblib.load(_ROOT / "ml" / "data" / "processed" / "encoder.joblib")
    print("  Loaded XGBoost model, scaler, and encoder.")

    # 3. Load dataset
    arff_path = _ROOT / "ml" / "data" / "raw" / "nsl_kdd" / "KDDTest+.arff"
    print(f"  Loading {arff_path.name} ...")
    df = load_arff(arff_path)

    # 4. Prepare try-calling agent pipeline
    try:
        from pipeline import run_pipeline
        can_use_llm = True
    except Exception:
        can_use_llm = False

    now = datetime.now(timezone.utc)
    total = len(CURATED_INDICES)
    print(f"  Processing {total} curated events through full detection pipeline...")

    seeded_docs = []

    for idx, row_idx in enumerate(CURATED_INDICES):
        row = df.iloc[row_idx]
        raw_event = {col: row[col] for col in FEATURE_COLS}

        # ML Inference
        row_dict = {col: str(raw_event[col]) if col in CATEGORICAL_COLS else float(raw_event[col]) for col in FEATURE_COLS}
        row_df = pd.DataFrame([row_dict], columns=FEATURE_COLS)
        cat_encoded = encoder.transform(row_df[CATEGORICAL_COLS])
        num_scaled = scaler.transform(row_df[NUMERIC_COLS].values.astype(np.float64))
        X = np.hstack([num_scaled, cat_encoded])

        pred_int = int(model.predict(X)[0])
        pred_label = "anomaly" if pred_int == 1 else "normal"
        confidence = float(model.predict_proba(X)[0][pred_int])

        # YARA Signatures
        sigs = match_signatures(raw_event)
        ml_flagged = pred_label == "anomaly"
        sig_flagged = len(sigs) > 0
        should_triage = ml_flagged or sig_flagged

        # ATT&CK Techniques
        attack_techniques = map_attack_techniques(raw_event)

        # Agent Triage
        triage_text = ""
        severity = "Low"
        justification = ""
        action = "none"

        if should_triage:
            t0 = time.perf_counter()
            triaged = None
            if can_use_llm and idx < 5:  # Run live Groq for the first few to demonstrate live agent, fallback for speed
                try:
                    triaged = await asyncio.wait_for(asyncio.to_thread(run_pipeline, raw_event), timeout=5.0)
                except Exception:
                    triaged = None

            if not triaged or not triaged.get("severity") or triaged.get("severity") == "UNKNOWN":
                triaged = fallback_triage(raw_event, attack_techniques, sigs)

            triage_text = triaged.get("triage", "")
            severity = triaged.get("severity", "Medium")
            justification = triaged.get("severity_justification", "")
            action = triaged.get("recommended_action", "flag_for_review")
            latency = round(time.perf_counter() - t0, 2)
        else:
            triage_text = "Clean connection conforming to standard baseline traffic patterns."
            severity = "Low"
            justification = "Normal network activity with no suspicious heuristics."
            action = "none"
            latency = 0.05

        # IP Enrichment
        ip_enrich = await enrich_ip(raw_event)

        # Staggered timestamp (spread over last 60 minutes)
        minutes_ago = 58 - int((idx / total) * 56)
        event_time = now - timedelta(minutes=minutes_ago, seconds=random.randint(5, 50))
        time_str = event_time.isoformat()

        event_id = uuid.uuid4().hex[:8]

        # Assemble full event message
        message = {
            "event_id": event_id,
            "event_index": idx + 1,
            "timestamp": time_str,
            "raw_event": raw_event,
            "prediction": pred_label,
            "confidence": round(confidence, 4),
            "source": "replay",
            "detection": {
                "prediction": pred_label,
                "confidence": round(confidence, 4),
                "ml_flagged": ml_flagged,
                "signature_flagged": sig_flagged,
            },
            "triage": triage_text,
            "severity": severity,
            "severity_justification": justification,
            "recommended_action": action,
            "attack_techniques": attack_techniques,
            "signature_matches": sigs,
            "ip_enrichment": ip_enrich,
            "ml_flagged": ml_flagged,
            "sig_flagged": sig_flagged,
            "agent_latency_seconds": latency,
        }

        # Calculate Risk Score
        risk = calculate_risk_score(message)
        message["risk_score"] = risk["risk_score"]
        message["risk_classification"] = risk["risk_classification"]
        message["risk_signals"] = risk["risk_signals"]

        # Configure realistic pre-resolved statuses for a subset of events
        if idx == 4:  # Pre-approved event
            message["status"] = "approved"
            message["resolved_by"] = "lead_analyst"
            message["resolved_at"] = (event_time + timedelta(minutes=3)).isoformat()
            message["action_executed"] = message["recommended_action"]
        elif idx == 8:  # Pre-rejected event
            message["status"] = "rejected"
            message["resolved_by"] = "sec_analyst"
            message["resolved_at"] = (event_time + timedelta(minutes=4)).isoformat()
            message["action_declined"] = message["recommended_action"]
        elif idx == 11:  # Under active investigation
            message["status"] = "investigating"
            message["updated_by"] = "soc_tier2"
        elif idx == 14:  # Resolved as false positive
            message["status"] = "false_positive"
            message["resolved_by"] = "senior_analyst"
            message["resolved_at"] = (event_time + timedelta(minutes=2)).isoformat()
        else:
            message["status"] = "pending_review"

        seeded_docs.append(to_python_types(message))
        print(f"  [{idx+1:02d}/{total}] {pred_label.upper():7s} | Sev: {severity:8s} | Risk: {risk['risk_score']:2d} ({risk['risk_classification']:8s}) | Status: {message['status']}")

    # Insert into MongoDB
    await database.events.insert_many(seeded_docs)
    count = await database.events.count_documents({})
    print()
    print("=" * 70)
    print(f"  SUCCESS: Seeded {count} events into MongoDB.")
    print("  Status breakdown:")
    print(f"    - Pending review : {sum(1 for e in seeded_docs if e['status'] == 'pending_review')}")
    print(f"    - Approved       : {sum(1 for e in seeded_docs if e['status'] == 'approved')}")
    print(f"    - Rejected       : {sum(1 for e in seeded_docs if e['status'] == 'rejected')}")
    print(f"    - Investigating  : {sum(1 for e in seeded_docs if e['status'] == 'investigating')}")
    print(f"    - False Positive : {sum(1 for e in seeded_docs if e['status'] == 'false_positive')}")
    print("  Dashboard is immediately populated and judge-ready!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(seed_events())
