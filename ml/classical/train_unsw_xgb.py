"""SentinelAI -- Train UNSW-NB15 XGBoost Classifier.

Trains an XGBoost model on the 41 features shared by BOTH the full-file layout
and the training/testing-set layout.

Crucial requirements:
- Features dropped: srcip, dstip, sport, dsport, Stime, Ltime, id, rate
- Do NOT compute or invent a 'rate' column
- Clean attack_cat: strip whitespace, merge Backdoor/Backdoors, fill blank with Normal
- Save model pipeline to ml/results/unsw_nb15_xgb.joblib
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from xgboost import XGBClassifier

# Path setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_PATH = PROJECT_ROOT / "ml" / "data" / "raw" / "UNSW_NB15_training-set.csv"
OUTPUT_DIR = PROJECT_ROOT / "ml" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = OUTPUT_DIR / "unsw_nb15_xgb.joblib"
METRICS_PATH = OUTPUT_DIR / "unsw_nb15_xgb_metrics.json"

# The 41 features shared by both layouts
UNSW_SHARED_FEATURES: list[str] = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", "dinpkt",
    "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt", "synack",
    "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"
]

CATEGORICAL_COLS: list[str] = ["proto", "service", "state"]
NUMERIC_COLS: list[str] = [c for c in UNSW_SHARED_FEATURES if c not in CATEGORICAL_COLS]


def clean_attack_cat(val: object) -> str:
    """Strip whitespace, merge Backdoor/Backdoors, fill blank with Normal."""
    if val is None or pd.isna(val):
        return "Normal"
    s = str(val).strip()
    if not s or s.lower() in ("-", "none", "nan", "null"):
        return "Normal"
    if s.lower() in ("backdoor", "backdoors"):
        return "Backdoors"
    return s


def train_unsw_model() -> dict:
    print(f"Loading UNSW training dataset from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH)
    print(f"Loaded raw dataset with shape: {df.shape}")

    # Clean attack_cat
    df["attack_cat"] = df["attack_cat"].apply(clean_attack_cat)

    # Clean categoricals and numerics
    for c in CATEGORICAL_COLS:
        df[c] = df[c].fillna("-").astype(str).str.strip().str.lower()

    for c in NUMERIC_COLS:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)

    # Validate that 'rate' and 'id' are NOT in features
    X = df[UNSW_SHARED_FEATURES].copy()
    y = df["label"].astype(int)

    print(f"Training on {len(UNSW_SHARED_FEATURES)} shared features (no 'rate', no 'id').")

    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Build scikit-learn Pipeline with ColumnTransformer
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERIC_COLS),
            ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL_COLS),
        ]
    )

    classifier = XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1,
    )

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", classifier),
    ])

    print("Fitting XGBoost pipeline on UNSW-NB15 shared features ...")
    t0 = time.time()
    pipeline.fit(X_train, y_train)
    training_time = time.time() - t0
    print(f"Training complete in {training_time:.2f}s")

    # Evaluate
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "model_name": "unsw_nb15_xgb",
        "dataset": "UNSW-NB15",
        "features_count": len(UNSW_SHARED_FEATURES),
        "shared_features": UNSW_SHARED_FEATURES,
        "categorical_columns": CATEGORICAL_COLS,
        "numeric_columns": NUMERIC_COLS,
        "training_time_seconds": round(training_time, 2),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
    }

    print("\n--- Model Evaluation ---")
    print(f"Accuracy : {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall   : {rec * 100:.2f}%")
    print(f"F1-Score : {f1 * 100:.2f}%")

    # Save model artifact bundle
    artifact_payload = {
        "pipeline": pipeline,
        "shared_features": UNSW_SHARED_FEATURES,
        "categorical_cols": CATEGORICAL_COLS,
        "numeric_cols": NUMERIC_COLS,
        "metrics": metrics,
    }

    joblib.dump(artifact_payload, MODEL_PATH)
    print(f"Saved model artifact to {MODEL_PATH}")

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved metrics to {METRICS_PATH}")

    return metrics


if __name__ == "__main__":
    train_unsw_model()
