"""Unit tests for ML Preprocessing consistency (train vs inference).

Verifies:
- Scaler and OneHotEncoder consistency with training artifacts
- Feature count and dimensionality: 38 numeric + 84 categorical = 122 features
- Shape alignment with train_X.npy and test_X.npy
- Graceful handling of unseen categorical values (handle_unknown='ignore')
"""

from __future__ import annotations

from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_PROCESSED = _PROJECT_ROOT / "ml" / "data" / "processed"

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


@pytest.fixture
def preprocessors():
    scaler_path = _DATA_PROCESSED / "scaler.joblib"
    encoder_path = _DATA_PROCESSED / "encoder.joblib"
    assert scaler_path.exists(), f"Scaler not found at {scaler_path}"
    assert encoder_path.exists(), f"Encoder not found at {encoder_path}"

    scaler = joblib.load(scaler_path)
    encoder = joblib.load(encoder_path)
    return scaler, encoder


def test_scaler_feature_count(preprocessors):
    scaler, _ = preprocessors
    assert scaler.n_features_in_ == len(NUMERIC_COLS), (
        f"Scaler expects {scaler.n_features_in_} features, expected {len(NUMERIC_COLS)}"
    )
    assert len(NUMERIC_COLS) == 38


def test_encoder_categorical_columns(preprocessors):
    _, encoder = preprocessors
    assert encoder.n_features_in_ == len(CATEGORICAL_COLS), (
        f"Encoder expects {encoder.n_features_in_} categoricals, expected {len(CATEGORICAL_COLS)}"
    )
    assert len(CATEGORICAL_COLS) == 3


def test_total_transformed_dimensions(preprocessors):
    scaler, encoder = preprocessors

    # Create dummy sample
    sample_dict = {col: 0.0 for col in NUMERIC_COLS}
    sample_dict.update({"protocol_type": "tcp", "service": "http", "flag": "SF"})
    df = pd.DataFrame([sample_dict])

    cat_encoded = encoder.transform(df[CATEGORICAL_COLS])
    num_scaled = scaler.transform(df[NUMERIC_COLS].values.astype(np.float64))

    X = np.hstack([num_scaled, cat_encoded])

    assert X.shape == (1, 122), f"Expected shape (1, 122), got {X.shape}"
    assert num_scaled.shape[1] == 38
    assert cat_encoded.shape[1] == 84


def test_alignment_with_processed_data():
    """Ensure runtime transformation matches offline preprocessed arrays."""
    train_x_path = _DATA_PROCESSED / "train_X.npy"
    test_x_path = _DATA_PROCESSED / "test_X.npy"

    if train_x_path.exists():
        train_X = np.load(train_x_path, mmap_mode="r")
        assert train_X.shape[1] == 122, f"train_X features {train_X.shape[1]} != 122"

    if test_x_path.exists():
        test_X = np.load(test_x_path, mmap_mode="r")
        assert test_X.shape[1] == 122, f"test_X features {test_X.shape[1]} != 122"


def test_unseen_categorical_graceful_handling(preprocessors):
    """Unseen categorical labels should produce all-zero one-hot vectors without crashing."""
    scaler, encoder = preprocessors

    weird_dict = {col: 0.0 for col in NUMERIC_COLS}
    weird_dict.update({
        "protocol_type": "alien_protocol",
        "service": "unknown_future_service",
        "flag": "FLAG_XYZ",
    })
    df = pd.DataFrame([weird_dict])

    cat_encoded = encoder.transform(df[CATEGORICAL_COLS])
    num_scaled = scaler.transform(df[NUMERIC_COLS].values.astype(np.float64))
    X = np.hstack([num_scaled, cat_encoded])

    assert X.shape == (1, 122)
    assert np.all(cat_encoded == 0), "Unseen categories should encode to zeros"
