"""SentinelAI -- Automated Tests for Dataset Upload & Schema Mapping.

Validates:
1. Strict schema detection for NSL-KDD, CICIDS2017, and UNSW-NB15.
2. Rejection of invalid schemas without guessing (returns missing/unexpected columns).
3. Mapping of all three schemas onto the trained 41-feature NSL-KDD schema.
4. Fast preprocessing + inference with XGBoost and Random Forest.
5. FastAPI integration tests for POST /dataset/upload and GET /dataset/sample/{template}.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

# Ensure backend/ and tests/ are in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_backend_dir = str(_PROJECT_ROOT / "backend")
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from dataset_adapter import (
    NSL_KDD_FEATURE_COLS,
    CATEGORICAL_COLS,
    NUMERIC_COLS,
    SchemaDetectionError,
    detect_schema,
    generate_sample_csv,
    map_dataset_to_nsl_kdd,
    process_csv_upload,
)
from main import app, _load_artifacts


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def setup_models():
    """Ensure artifacts are loaded before running tests."""
    _load_artifacts()


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


# ---------------------------------------------------------------------------
# Unit Tests: Schema Detection
# ---------------------------------------------------------------------------

def test_detect_schema_nsl_kdd():
    """NSL-KDD with 41 canonical columns is detected strictly."""
    cols = list(NSL_KDD_FEATURE_COLS)
    result = detect_schema(cols)
    assert result.schema_name == "NSL-KDD"
    assert "Detected format: NSL-KDD" in result.format_display
    assert result.matched_columns_count == 41
    assert len(result.missing_template_columns) == 0


def test_detect_schema_cicids2017():
    """CICIDS2017 with typical CICFlowMeter headers is detected."""
    cic_cols = [
        " Destination Port", " Flow Duration", " Total Fwd Packets",
        " Total Backward Packets", "Total Length of Fwd Packets",
        " Total Length of Bwd Packets", " Flow Bytes/s", " Flow Packets/s",
        " Flow IAT Mean", " FIN Flag Count", " SYN Flag Count",
        " RST Flag Count", " PSH Flag Count", " ACK Flag Count",
        " URG Flag Count", "Init_Win_bytes_forward", " Label",
    ]
    result = detect_schema(cic_cols)
    assert result.schema_name == "CICIDS2017"
    assert "Detected format: CICIDS2017" in result.format_display
    assert result.matched_columns_count >= 15


def test_detect_schema_unsw_nb15():
    """UNSW-NB15 with standard Argus/Bro headers is detected."""
    unsw_cols = [
        "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
        "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "ct_srv_src",
        "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
        "ct_dst_src_ltm", "is_ftp_login", "is_sm_ips_ports", "attack_cat", "label",
    ]
    result = detect_schema(unsw_cols)
    assert result.schema_name == "UNSW-NB15"
    assert "Detected format: UNSW-NB15" in result.format_display
    assert result.matched_columns_count >= 20


def test_detect_schema_invalid_strict():
    """Arbitrary/invalid CSV raises SchemaDetectionError detailing missing & unexpected columns."""
    invalid_cols = ["employee_id", "salary", "department", "hire_date", "performance_score"]
    with pytest.raises(SchemaDetectionError) as exc_info:
        detect_schema(invalid_cols)

    details = exc_info.value.details
    assert details["error"] == "schema_detection_failed"
    assert "templates_evaluated" in details
    assert "NSL-KDD" in details["templates_evaluated"]
    assert "CICIDS2017" in details["templates_evaluated"]
    assert "UNSW-NB15" in details["templates_evaluated"]
    # Check that missing columns are reported
    assert len(details["templates_evaluated"]["NSL-KDD"]["missing_key_columns"]) > 0
    # Check that uploaded columns are reported
    assert details["uploaded_columns_sample"] == invalid_cols


# ---------------------------------------------------------------------------
# Unit Tests: Feature Mapping Integrity
# ---------------------------------------------------------------------------

def test_feature_mapping_conforms_to_41_cols():
    """All detected templates map to exact 41 features with valid types and default tracking."""
    for template in ["nsl", "cic", "unsw"]:
        raw_csv = generate_sample_csv(template)
        mapped_res = process_csv_upload(raw_csv.encode(), max_rows=10)

        assert len(mapped_res.df_mapped.columns) == 41
        assert list(mapped_res.df_mapped.columns) == NSL_KDD_FEATURE_COLS
        assert mapped_res.total_rows > 0

        # Verify categorical columns are non-empty strings
        for cat_col in CATEGORICAL_COLS:
            vals = mapped_res.df_mapped[cat_col].tolist()
            assert all(isinstance(v, str) and len(v) > 0 for v in vals)

        # Verify numeric columns contain valid floats
        for num_col in NUMERIC_COLS:
            vals = mapped_res.df_mapped[num_col].tolist()
            assert all(isinstance(v, (int, float)) for v in vals)

        # Verify tracking lists
        assert len(mapped_res.columns_matched) > 0
        if template != "nsl":
            assert len(mapped_res.columns_defaulted) > 0


# ---------------------------------------------------------------------------
# Integration Tests: FastAPI Endpoints
# ---------------------------------------------------------------------------

def test_fastapi_upload_nsl_kdd(client):
    """POST /dataset/upload with NSL-KDD sample returns 200, correct display format, and alerts."""
    csv_content = generate_sample_csv("nsl").encode()
    response = client.post(
        "/dataset/upload",
        files={"file": ("nsl_test.csv", io.BytesIO(csv_content), "text/csv")},
        data={"model_type": "xgboost", "max_rows": 10},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert data["schema"] == "NSL-KDD"
    assert "Detected format: NSL-KDD" in data["format_display"]
    assert data["model_used"] == "XGBoost"
    assert data["processed_rows"] == 3
    assert data["anomalies_detected"] >= 1
    assert "alerts" in data
    assert len(data["alerts"]) >= 1


def test_fastapi_upload_cicids2017(client):
    """POST /dataset/upload with CICIDS2017 sample returns 200 and mapped alerts."""
    csv_content = generate_sample_csv("cic").encode()
    response = client.post(
        "/dataset/upload",
        files={"file": ("cicids_test.csv", io.BytesIO(csv_content), "text/csv")},
        data={"model_type": "xgboost", "max_rows": 10},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert data["schema"] == "CICIDS2017"
    assert "Detected format: CICIDS2017" in data["format_display"]
    assert data["processed_rows"] == 3
    assert "duration" in data["columns_matched"]
    assert len(data["columns_defaulted"]) > 0


def test_fastapi_upload_unsw_nb15(client):
    """POST /dataset/upload with UNSW-NB15 sample returns 200 and mapped alerts."""
    csv_content = generate_sample_csv("unsw").encode()
    response = client.post(
        "/dataset/upload",
        files={"file": ("unsw_test.csv", io.BytesIO(csv_content), "text/csv")},
        data={"model_type": "random_forest", "max_rows": 10},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert data["schema"] == "UNSW-NB15"
    assert "Detected format: UNSW-NB15" in data["format_display"]
    assert data["model_used"] == "Random Forest"
    assert data["processed_rows"] == 3


def test_fastapi_upload_invalid_schema_fails_cleanly(client):
    """POST /dataset/upload with unrecognized schema returns HTTP 400 with diagnostic report."""
    csv_content = generate_sample_csv("invalid").encode()
    response = client.post(
        "/dataset/upload",
        files={"file": ("invalid_finance.csv", io.BytesIO(csv_content), "text/csv")},
        data={"model_type": "xgboost", "max_rows": 10},
    )
    assert response.status_code == 400
    data = response.json()

    assert data["error"] == "schema_detection_failed"
    assert "templates_evaluated" in data
    assert "NSL-KDD" in data["templates_evaluated"]
    assert "uploaded_columns_sample" in data
    assert "customer_id" in data["uploaded_columns_sample"]


def test_fastapi_sample_endpoints(client):
    """GET /dataset/sample/{template} returns downloadable CSV files."""
    for template in ["nsl", "cic", "unsw", "invalid"]:
        res = client.get(f"/dataset/sample/{template}")
        assert res.status_code == 200
        assert "text/csv" in res.headers.get("content-type", "")
        assert len(res.text) > 0
