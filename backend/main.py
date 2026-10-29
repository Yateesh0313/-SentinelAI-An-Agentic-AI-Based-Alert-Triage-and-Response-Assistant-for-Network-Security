"""SentinelAI Backend -- FastAPI with ML detection, agent triage, and approval.

Loads the trained XGBoost model and preprocessing objects (scaler, encoder)
at startup, then exposes:
  GET  /health                      -- health check
  POST /detect                      -- classify a raw network event
  POST /triage                      -- detect + run full agent pipeline
  POST /events/{id}/approve         -- approve a pending event's action
  POST /events/{id}/reject          -- reject a pending event's action
  POST /events/{id}/investigate     -- mark event as under investigation
  POST /events/{id}/false_positive  -- mark event as false positive
  GET  /events/{id}                 -- get event status
  GET  /events/pending              -- list pending events
  GET  /stats/overview              -- aggregated counts by severity/status/source
  GET  /replay/start                -- start streaming via WebSocket
  GET  /replay/stop                 -- stop the replay stream
  WS   /ws                          -- WebSocket for live event stream
"""

from __future__ import annotations

import asyncio
import json as json_module
import logging
import os
import sys
import time as time_module
import traceback as tb_module
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from dotenv import load_dotenv
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Phase 18: Research Mode configuration
# ---------------------------------------------------------------------------

load_dotenv()

RESEARCH_MODE: bool = os.getenv("RESEARCH_MODE", "false").lower() in ("true", "1", "yes")


def _require_research_mode() -> None:
    """Raise 403 if RESEARCH_MODE is disabled.

    Called at the top of honeypot/live-capture endpoints so they
    return a clear JSON error instead of raw crashes in demo mode.
    """
    if not RESEARCH_MODE:
        raise HTTPException(
            status_code=403,
            detail="Research Mode is disabled. Set RESEARCH_MODE=true in backend/.env to enable this feature.",
        )


logger = logging.getLogger("sentinelai")

from auth import (
    LoginRequest,
    RegisterRequest,
    get_current_user,
    get_optional_user,
    login_user,
    register_user,
    require_role,
    validate_ws_token,
)
from enrichment import generate_simulated_ip

# Add agents/ to sys.path so we can import the pipeline
_PROJECT_ROOT_EARLY = Path(__file__).resolve().parent.parent
_agents_dir = str(_PROJECT_ROOT_EARLY / "agents")
if _agents_dir not in sys.path:
    sys.path.insert(0, _agents_dir)

# Add ml/signatures/ to sys.path for the YARA signature matcher
_signatures_dir = str(_PROJECT_ROOT_EARLY / "ml" / "signatures")
if _signatures_dir not in sys.path:
    sys.path.insert(0, _signatures_dir)

# Add ml/honeypot/ to sys.path for the honeypot listener
_honeypot_dir = str(_PROJECT_ROOT_EARLY / "ml" / "honeypot")
if _honeypot_dir not in sys.path:
    sys.path.insert(0, _honeypot_dir)

# Add ml/live_capture/ to sys.path for the Suricata ingestor
_live_capture_dir = str(_PROJECT_ROOT_EARLY / "ml" / "live_capture")
if _live_capture_dir not in sys.path:
    sys.path.insert(0, _live_capture_dir)

# ---------------------------------------------------------------------------
# Paths to Phase 3/4 artifacts
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_PROCESSED_DIR = _PROJECT_ROOT / "ml" / "data" / "processed"
_RESULTS_DIR = _PROJECT_ROOT / "ml" / "results"

# The 41 raw feature columns in NSL-KDD order (excluding 'class')
FEATURE_COLS: list[str] = [
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

CATEGORICAL_COLS: list[str] = ["protocol_type", "service", "flag"]
NUMERIC_COLS: list[str] = [c for c in FEATURE_COLS if c not in CATEGORICAL_COLS]

# ---------------------------------------------------------------------------
# Global model/transformer holders (loaded once at startup)
# ---------------------------------------------------------------------------

_model: Any = None
_model_rf: Any = None
_scaler: Any = None
_encoder: Any = None
_model_unsw: Any = None
_unsw_features: list[str] = []


def _load_artifacts() -> None:
    """Load the trained model and preprocessing objects into module globals."""
    global _model, _model_rf, _scaler, _encoder, _model_unsw, _unsw_features

    model_path = _RESULTS_DIR / "classical_baseline_model.joblib"
    rf_path = _RESULTS_DIR / "classical_rf_model.joblib"
    scaler_path = _PROCESSED_DIR / "scaler.joblib"
    encoder_path = _PROCESSED_DIR / "encoder.joblib"
    unsw_path = _RESULTS_DIR / "unsw_nb15_xgb.joblib"

    for p in [model_path, scaler_path, encoder_path]:
        if not p.exists():
            raise FileNotFoundError(
                f"Required artifact not found: {p}\n"
                "Run Phase 3 (loader) and Phase 4 (training) first."
            )

    _model = joblib.load(model_path)
    _scaler = joblib.load(scaler_path)
    _encoder = joblib.load(encoder_path)

    print(f"  [startup] Loaded model (XGBoost) : {model_path.name}")
    if rf_path.exists():
        _model_rf = joblib.load(rf_path)
        print(f"  [startup] Loaded model (RF)      : {rf_path.name}")
    print(f"  [startup] Loaded scaler          : {scaler_path.name}")
    print(f"  [startup] Loaded encoder         : {encoder_path.name}")

    if unsw_path.exists():
        try:
            unsw_data = joblib.load(unsw_path)
            _model_unsw = unsw_data.get("pipeline")
            _unsw_features = unsw_data.get("shared_features", [])
            print(f"  [startup] Loaded model (UNSW XGB): {unsw_path.name} ({len(_unsw_features)} features)")
        except Exception as exc:
            print(f"  [startup] WARNING: Failed to load unsw_nb15_xgb: {exc}")



# ---------------------------------------------------------------------------
# Lifespan (startup/shutdown)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ML artifacts, agent pipeline, YARA rules, and connect to MongoDB."""
    print("SentinelAI Backend starting up ...")
    _load_artifacts()

    # Pre-load the agent pipeline (compiles the LangGraph)
    try:
        from pipeline import get_graph  # noqa: F811
        get_graph()
        print("  [startup] Agent pipeline loaded.")
    except Exception as exc:
        print(f"  [startup] WARNING: Agent pipeline failed to load: {exc}")
        print("  [startup] /triage and agent-enriched replay will not work.")

    # Pre-compile YARA rules
    try:
        from matcher import _load_rules  # noqa: F811
        _load_rules()
    except Exception as exc:
        print(f"  [startup] WARNING: YARA rules failed to load: {exc}")

    # Connect to MongoDB
    try:
        import database as db_module
        await db_module.connect()
    except Exception as exc:
        print(f"  [startup] WARNING: MongoDB connection failed: {exc}")

    print("  [startup] Ready.")
    yield

    # Shutdown
    try:
        import database as db_module
        await db_module.disconnect()
    except Exception:
        pass
    print("SentinelAI Backend shutting down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SentinelAI Backend",
    description="Agentic AI Alert Triage & Response Assistant for Network Security",
    version="0.18.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Phase 18: Global exception handler (safety net for unhandled errors)
# ---------------------------------------------------------------------------

from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception):
    """Catch-all handler so no raw Python traceback ever reaches the client.

    Logs the full traceback server-side for debugging, but returns a
    generic safe JSON message to the caller.
    """
    # Don't intercept HTTP exceptions or request validation errors
    if isinstance(exc, (HTTPException, StarletteHTTPException, RequestValidationError)):
        raise exc
    logger.error(
        "Unhandled exception on %s %s:\n%s",
        request.method, request.url, tb_module.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "detail": "An unexpected error occurred. Please try again or contact support.",
        },
    )


# ---------------------------------------------------------------------------
# Event store -- now backed by MongoDB (Phase 10)
# ---------------------------------------------------------------------------

import database as db
from enrichment import enrich_ip
from matcher import match_signatures
from listener import HoneypotListener
from suricata_ingest import SuricataIngestor
from risk_scoring import calculate_risk_score
from csv_exporter import (
    append_honeypot_log,
    export_honeypot_csv,
    export_suricata_csv,
    list_exported_csvs,
    get_latest_csv,
)
from dataset_adapter import (
    process_csv_upload,
    generate_sample_csv,
    SchemaDetectionError,
)
from interface_detect import (
    detect_interfaces,
    get_default_interface,
)



async def _store_event(event_data: dict[str, Any]) -> str:
    """Assign a unique event_id, persist to MongoDB, return the id."""
    event_id = str(uuid.uuid4())[:8]
    try:
        await db.insert_event(event_data, event_id)
    except Exception as exc:
        logger.warning("MongoDB storage failed for event %s: %s", event_id, exc)
    return event_id


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str


class NetworkEvent(BaseModel):
    """Raw network event with 41 NSL-KDD features.

    All fields are accepted as flexible types (str/float) since
    categorical values come as strings and numerics as numbers.
    """
    duration: float = 0
    protocol_type: str = "tcp"
    service: str = "http"
    flag: str = "SF"
    src_bytes: float = 0
    dst_bytes: float = 0
    land: float = 0
    wrong_fragment: float = 0
    urgent: float = 0
    hot: float = 0
    num_failed_logins: float = 0
    logged_in: float = 0
    num_compromised: float = 0
    root_shell: float = 0
    su_attempted: float = 0
    num_root: float = 0
    num_file_creations: float = 0
    num_shells: float = 0
    num_access_files: float = 0
    num_outbound_cmds: float = 0
    is_host_login: float = 0
    is_guest_login: float = 0
    count: float = 0
    srv_count: float = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    dst_host_count: float = 0
    dst_host_srv_count: float = 0
    dst_host_same_srv_rate: float = 0
    dst_host_diff_srv_rate: float = 0
    dst_host_same_src_port_rate: float = 0
    dst_host_srv_diff_host_rate: float = 0
    dst_host_serror_rate: float = 0
    dst_host_srv_serror_rate: float = 0
    dst_host_rerror_rate: float = 0
    dst_host_srv_rerror_rate: float = 0


class DetectResponse(BaseModel):
    prediction: str
    confidence: float
    signature_matches: list[dict]
    raw_event: dict


# ---------------------------------------------------------------------------
# Inference helper
# ---------------------------------------------------------------------------

def run_inference(event: NetworkEvent, model_type: str = "xgboost") -> tuple[str, float]:
    """Preprocess a raw event and run the loaded model (XGBoost or Random Forest).

    Uses the SAME scaler/encoder from Phase 3 to guarantee consistency
    with Phase 4 training.

    Returns (prediction_label, confidence_score).
    """
    # Select active model
    active_model = _model_rf if (_model_rf is not None and model_type.lower() in ("rf", "random_forest")) else _model
    if active_model is None:
        raise RuntimeError("Detection model is not loaded.")

    # Build a single-row DataFrame matching training column order
    row_dict: dict[str, Any] = {}
    for col in FEATURE_COLS:
        val = getattr(event, col)
        if col in CATEGORICAL_COLS:
            row_dict[col] = str(val)
        else:
            row_dict[col] = float(val)

    row_df = pd.DataFrame([row_dict], columns=FEATURE_COLS)

    # Encode categoricals (handle_unknown='ignore' already set in the encoder)
    cat_encoded = _encoder.transform(row_df[CATEGORICAL_COLS])

    # Scale numerics
    num_scaled = _scaler.transform(
        row_df[NUMERIC_COLS].values.astype(np.float64)
    )

    # Combine: same order as training (numeric first, then one-hot)
    X = np.hstack([num_scaled, cat_encoded])

    # Predict
    pred = active_model.predict(X)[0]
    label = "anomaly" if pred == 1 else "normal"

    # Confidence from predict_proba
    proba = active_model.predict_proba(X)[0]
    confidence = float(proba[pred])

    return label, round(confidence, 4)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def root() -> dict:
    """Root endpoint — API overview."""
    try:
        return {
            "app": "SentinelAI Backend",
            "version": "0.18.0",
            "status": "running",
            "research_mode": RESEARCH_MODE,
            "endpoints": {
                "GET /": "This overview",
                "GET /config/mode": "Current operating mode (demo/research)",
                "POST /detect": "Classify a single network event (ML + signatures)",
                "POST /triage": "Detect + full agent pipeline if flagged",
                "GET /replay/start": "Start streaming KDDTest+ events via WebSocket",
                "GET /replay/stop": "Stop the replay stream",
                "GET /honeypot/start": "Start the honeypot listener (RESEARCH_MODE only)",
                "GET /honeypot/stop": "Stop the honeypot listener (RESEARCH_MODE only)",
                "GET /honeypot/status": "Check honeypot listener status",
                "GET /interfaces": "List available network interfaces (excluding Bluetooth)",
                "GET /suricata/start": "Start Suricata IDS engine (RESEARCH_MODE only)",
                "GET /suricata/stop": "Stop Suricata IDS engine (RESEARCH_MODE only)",
                "GET /suricata/status": "Check Suricata IDS engine status",
                "POST /events/{id}/approve": "Approve a pending event",
                "POST /events/{id}/reject": "Reject a pending event",
                "POST /events/{id}/investigate": "Mark event as investigating",
                "POST /events/{id}/false_positive": "Mark event as false positive",
                "GET /stats/overview": "Aggregated counts by severity/status/source",
                "WS /ws": "WebSocket for live event stream",
                "GET /docs": "Interactive API docs (Swagger UI)",
            },
        }
    except Exception as exc:
        logger.error("Error in root endpoint: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load API overview.")


@app.get("/config/mode")
async def config_mode() -> dict:
    """Return the current operating mode so the frontend can adapt its UI."""
    return {"research_mode": RESEARCH_MODE}


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return a simple health-check JSON response."""
    return HealthResponse(status="ok")


@app.post("/detect", response_model=DetectResponse)
async def detect(
    event: NetworkEvent,
    current_user: dict = Depends(get_current_user),
) -> DetectResponse:
    """Classify a raw network event as normal or anomaly.

    Runs TWO parallel detection methods:
      1. ML-based: Phase 4 XGBoost model (anomaly/normal prediction)
      2. Signature-based: Phase 13 YARA rules (known-bad pattern matching)

    Both results are returned independently — they can agree or disagree.
    """
    if _model is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Backend may still be starting up.",
        )

    try:
        label, confidence = run_inference(event)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Inference error: {exc}",
        )

    # Run YARA signature matching (separate from ML)
    try:
        raw = event.model_dump()
        sig_matches = match_signatures(raw)
    except Exception as exc:
        logger.error("YARA signature matching error: %s", exc)
        raw = event.model_dump()
        sig_matches = []

    return DetectResponse(
        prediction=label,
        confidence=confidence,
        signature_matches=sig_matches,
        raw_event=raw,
    )


@app.post("/triage")
async def triage(
    event: NetworkEvent,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Detect + run full agent pipeline on a single event.

    Hybrid detection: if EITHER the ML model flags anomaly OR a YARA
    signature matches, the event goes through the agent pipeline.
    This is deliberate — signatures and ML can disagree, and both
    signals are valuable.
    """
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")

    # Step 1: ML Detection
    try:
        label, confidence = run_inference(event)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Inference error: {exc}")

    raw = event.model_dump()

    # Step 1b: Signature Detection (parallel, independent)
    try:
        sig_matches = match_signatures(raw)
    except Exception as exc:
        logger.error("YARA matching error in triage: %s", exc)
        sig_matches = []
    sig_names = [m["rule"] for m in sig_matches]

    # Determine if agent pipeline should run:
    # ML anomaly OR any signature match
    ml_flagged = label == "anomaly"
    sig_flagged = len(sig_matches) > 0
    should_triage = ml_flagged or sig_flagged

    result: dict[str, Any] = {
        "raw_event": raw,
        "detection": {
            "prediction": label,
            "confidence": confidence,
            "ml_flagged": ml_flagged,
            "signature_flagged": sig_flagged,
        },
        "signature_matches": sig_matches,
    }

    try:
        # Step 2: If either method flags, run agent pipeline
        if should_triage:
            trigger = "ml+sig" if (ml_flagged and sig_flagged) else ("ml" if ml_flagged else "sig")
            try:
                from pipeline import run_pipeline  # noqa: F811

                t0 = time_module.perf_counter()
                agent_result = await asyncio.to_thread(run_pipeline, raw)
                agent_time = time_module.perf_counter() - t0

                result["triage"] = agent_result.get("triage", "")
                result["severity"] = agent_result.get("severity", "UNKNOWN")
                result["severity_justification"] = agent_result.get(
                    "severity_justification", ""
                )
                result["recommended_action"] = agent_result.get(
                    "recommended_action", "flag_for_review"
                )
                result["attack_techniques"] = agent_result.get(
                    "attack_techniques", []
                )
                result["agent_latency_seconds"] = round(agent_time, 2)

                # Step 3: IP enrichment (simulated IP for NSL-KDD data)
                try:
                    enrichment_data = await enrich_ip(raw)
                    result["ip_enrichment"] = enrichment_data
                except Exception as enrich_exc:
                    print(f"  [triage] Enrichment error: {enrich_exc}")
                    result["ip_enrichment"] = None

                # Step 4: Formula-based risk score (Phase 17)
                risk = calculate_risk_score({
                    **result,
                    "prediction": label,
                    "confidence": confidence,
                    "source": result.get("source", "unknown"),
                })
                result["risk_score"]          = risk["risk_score"]
                result["risk_classification"] = risk["risk_classification"]
                result["risk_signals"]        = risk["risk_signals"]

                # Store in event store with unique ID
                event_id = await _store_event(result.copy())
                result["event_id"] = event_id
                result["status"] = "pending_review"

                print(f"  [triage] Agent chain completed in {agent_time:.2f}s "
                      f"-> {result['severity']} (LLM) / {risk['risk_score']} {risk['risk_classification']} (formula) "
                      f"action={result['recommended_action']} [{event_id}]")

            except Exception as exc:
                try:
                    from pipeline import heuristic_triage
                    fb = heuristic_triage(raw)
                    result["triage"] = fb["triage"]
                    result["severity"] = fb["severity"]
                    result["severity_justification"] = fb["severity_justification"]
                    result["recommended_action"] = fb["recommended_action"]
                except Exception:
                    result["triage"] = "Anomalous traffic pattern detected requiring analyst verification."
                    result["severity"] = "Medium"
                    result["severity_justification"] = f"Fallback triage (Agent error: {exc})"
                    result["recommended_action"] = "flag_for_review"

                result["attack_techniques"] = []
                result["ip_enrichment"] = None
                result["agent_latency_seconds"] = 0
                # Compute risk score from available signals
                risk = calculate_risk_score({
                    **result,
                    "prediction": label,
                    "confidence": confidence,
                })
                result["risk_score"]          = risk["risk_score"]
                result["risk_classification"] = risk["risk_classification"]
                result["risk_signals"]        = risk["risk_signals"]
                event_id = await _store_event(result.copy())
                result["event_id"] = event_id
                result["status"] = "pending_review"
                print(f"  [triage] Agent pipeline fallback used ({exc}) -> {result['severity']} [{event_id}]")

        else:
            # Neither method flagged -- skip agent pipeline
            result["triage"] = None
            result["severity"] = None
            result["severity_justification"] = None
            result["recommended_action"] = None
            result["attack_techniques"] = None
            result["ip_enrichment"] = None
            result["agent_latency_seconds"] = 0
            result["event_id"] = None
            result["status"] = None
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Triage endpoint error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Triage processing error: {exc}")

    return result


# ---------------------------------------------------------------------------
# WebSocket + Replay
# ---------------------------------------------------------------------------

# In-memory replay state
_replay_running: bool = False
_replay_task: asyncio.Task | None = None
_ws_clients: list[WebSocket] = []

# Cached test DataFrame (loaded once on first replay)
_test_df: pd.DataFrame | None = None


def _load_test_data() -> pd.DataFrame:
    """Load raw KDDTest+ data via the Phase 3 loader (cached)."""
    global _test_df
    if _test_df is not None:
        return _test_df

    # Import the loader
    loader_dir = str(_PROJECT_ROOT / "ml" / "data")
    if loader_dir not in sys.path:
        sys.path.insert(0, loader_dir)
    from loader import load_arff  # noqa: E402

    test_path = _PROJECT_ROOT / "ml" / "data" / "raw" / "nsl_kdd" / "KDDTest+.arff"
    _test_df = load_arff(test_path)
    print(f"  [replay] Loaded {len(_test_df)} rows from KDDTest+")
    return _test_df


async def _broadcast(message: dict) -> None:
    """Send a JSON message to all connected WebSocket clients."""
    dead: list[WebSocket] = []
    text = json_module.dumps(message)
    for ws in _ws_clients:
        try:
            await ws.send_text(text)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


async def _replay_loop() -> None:
    """Stream KDDTest+ rows one per second with predictions.

    Anomalies are enriched with the full agent pipeline output.
    Normal events are pushed with detection-only data.
    """
    global _replay_running

    df = _load_test_data()
    print(f"  [replay] Starting replay of {len(df)} events ...")

    for idx in range(len(df)):
        if not _replay_running:
            print(f"  [replay] Stopped at row {idx}")
            break

        row = df.iloc[idx]
        actual_label = row["class"]

        # Build a NetworkEvent from the row
        payload: dict[str, Any] = {}
        for col in FEATURE_COLS:
            val = row[col]
            if col in CATEGORICAL_COLS:
                payload[col] = str(val)
            else:
                payload[col] = float(val)

        event = NetworkEvent(**payload)

        # Run inference
        try:
            prediction, confidence = run_inference(event)
        except Exception as exc:
            prediction = "error"
            confidence = 0.0
            print(f"  [replay] Inference error at row {idx}: {exc}")

        # Run YARA signature matching
        sig_matches = match_signatures(payload)
        ml_flagged = prediction == "anomaly"
        sig_flagged = len(sig_matches) > 0
        should_triage = ml_flagged or sig_flagged

        # Build message for WebSocket clients
        message: dict[str, Any] = {
            "event_index": idx,
            "raw_event": payload,
            "prediction": prediction,
            "confidence": confidence,
            "actual": actual_label,
            "source": "replay",  # Phase 15: tag detection path
            "signature_matches": sig_matches,
            "ml_flagged": ml_flagged,
            "sig_flagged": sig_flagged,
        }

        # If EITHER method flags, run agent pipeline
        if should_triage:
            trigger = "ml+sig" if (ml_flagged and sig_flagged) else ("ml" if ml_flagged else "sig")
            try:
                from pipeline import run_pipeline  # noqa: F811

                t0 = time_module.perf_counter()
                agent_result = await asyncio.to_thread(run_pipeline, payload)
                agent_time = time_module.perf_counter() - t0

                message["triage"] = agent_result.get("triage", "")
                message["severity"] = agent_result.get("severity", "UNKNOWN")
                message["severity_justification"] = agent_result.get(
                    "severity_justification", ""
                )
                message["recommended_action"] = agent_result.get(
                    "recommended_action", "flag_for_review"
                )
                message["attack_techniques"] = agent_result.get(
                    "attack_techniques", []
                )
                message["agent_latency_seconds"] = round(agent_time, 2)

                # IP enrichment (simulated IP for NSL-KDD replay)
                try:
                    enrichment_data = await enrich_ip(payload)
                    message["ip_enrichment"] = enrichment_data
                except Exception as enrich_exc:
                    print(f"  [replay] #{idx} Enrichment error: {enrich_exc}")
                    message["ip_enrichment"] = None

                # Phase 17: formula-based risk score
                risk = calculate_risk_score(message)
                message["risk_score"]          = risk["risk_score"]
                message["risk_classification"] = risk["risk_classification"]
                message["risk_signals"]        = risk["risk_signals"]

                # Store in event store and attach event_id + status
                event_id = await _store_event(message.copy())
                message["event_id"] = event_id
                message["status"] = "pending_review"

                sig_names = [m['rule'] for m in sig_matches]
                print(f"  [replay] #{idx} FLAGGED ({trigger}) -> {message['severity']} (LLM) "
                      f"risk={risk['risk_score']} {risk['risk_classification']} "
                      f"sigs={sig_names} [{event_id}]")

            except Exception as exc:
                try:
                    from pipeline import heuristic_triage
                    fb = heuristic_triage(payload)
                    message["triage"] = fb["triage"]
                    message["severity"] = fb["severity"]
                    message["severity_justification"] = fb["severity_justification"]
                    message["recommended_action"] = fb["recommended_action"]
                except Exception:
                    message["triage"] = "Anomalous traffic pattern detected requiring analyst verification."
                    message["severity"] = "Medium"
                    message["severity_justification"] = f"Fallback triage (Agent error: {exc})"
                    message["recommended_action"] = "flag_for_review"

                message["attack_techniques"] = []
                message["ip_enrichment"] = None
                message["agent_latency_seconds"] = 0
                risk = calculate_risk_score(message)
                message["risk_score"]          = risk["risk_score"]
                message["risk_classification"] = risk["risk_classification"]
                message["risk_signals"]        = risk["risk_signals"]
                event_id = await _store_event(message.copy())
                message["event_id"] = event_id
                message["status"] = "pending_review"
                print(f"  [replay] #{idx} Agent pipeline fallback used ({exc}) -> {message['severity']} [{event_id}]")
        else:
            message["event_id"] = None
            message["status"] = None
            try:
                from pipeline import heuristic_triage
                fb = heuristic_triage(payload)
                message["triage"] = fb["triage"]
                message["severity"] = fb["severity"]
                message["severity_justification"] = fb["severity_justification"]
                message["recommended_action"] = fb["recommended_action"]
            except Exception:
                pass
            # Log every 10th normal event
            if idx % 10 == 0:
                n_clients = len(_ws_clients)
                print(f"  [replay] #{idx} normal "
                      f"conf={confidence:.2f} clients={n_clients}")

        await _broadcast(message)
        await asyncio.sleep(1.0)

    _replay_running = False
    print("  [replay] Replay finished.")


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint for live event streaming.

    Requires JWT token as query parameter: ws://host/ws?token=<jwt>
    """
    # Authenticate before accepting the connection
    token = websocket.query_params.get("token")
    try:
        validate_ws_token(token)
    except Exception:
        await websocket.close(code=4001, reason="Authentication required")
        return
    await websocket.accept()
    _ws_clients.append(websocket)
    print(f"  [ws] Client connected. Total: {len(_ws_clients)}")
    try:
        while True:
            # Keep connection alive; ignore incoming messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("WebSocket error: %s", exc)
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)
        print(f"  [ws] Client disconnected. Total: {len(_ws_clients)}")


@app.get("/replay/start")
async def replay_start(
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Start replaying KDDTest+ events over WebSocket at 1 event/sec."""
    global _replay_running, _replay_task

    try:
        if _replay_running:
            return {"status": "already_running"}

        _replay_running = True
        _replay_task = asyncio.create_task(_replay_loop())
        return {"status": "started", "started_by": current_user["username"]}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Replay start error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to start replay: {exc}")


@app.get("/replay/stop")
async def replay_stop(
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Stop the replay stream."""
    global _replay_running, _replay_task

    try:
        if not _replay_running:
            return {"status": "not_running"}

        _replay_running = False
        if _replay_task:
            _replay_task.cancel()
            _replay_task = None
        return {"status": "stopped", "stopped_by": current_user["username"]}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Replay stop error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to stop replay: {exc}")


# ---------------------------------------------------------------------------
# Honeypot (Phase 15)
# ---------------------------------------------------------------------------

_honeypot: HoneypotListener | None = None


async def _honeypot_on_connection(event: dict) -> None:
    """Callback fired for each honeypot connection.

    Every connection to the honeypot is anomalous by construction.
    We skip the ML detection step (the honeypot IS the detection signal)
    and go straight to the agent triage pipeline.
    """
    hp_meta = event.pop("_honeypot", {})
    raw = event  # NSL-KDD-shaped event

    # Run YARA signatures (some may fire even on honeypot events)
    sig_matches = match_signatures(raw)

    message: dict[str, Any] = {
        "event_index": hp_meta.get("connection_id", 0),
        "raw_event": raw,
        "prediction": "honeypot",  # Special label — not ML-derived
        "confidence": 1.0,  # 100% — honeypot connections are anomalous by definition
        "source": "honeypot",
        "honeypot_meta": {
            "src_ip": hp_meta.get("src_ip", "unknown"),
            "src_port": hp_meta.get("src_port", 0),
            "dst_port": hp_meta.get("dst_port", 0),
            "probe_text": hp_meta.get("probe_text", ""),
            "probe_bytes_len": hp_meta.get("probe_bytes_len", 0),
        },
        "signature_matches": sig_matches,
        "ml_flagged": False,  # ML was not run
        "sig_flagged": len(sig_matches) > 0,
    }

    # Run agent triage pipeline (always — honeypot = always suspicious)
    try:
        from pipeline import run_pipeline  # noqa: F811

        t0 = time_module.perf_counter()
        agent_result = await asyncio.to_thread(run_pipeline, raw)
        agent_time = time_module.perf_counter() - t0

        message["triage"] = agent_result.get("triage", "")
        message["severity"] = agent_result.get("severity", "UNKNOWN")
        message["severity_justification"] = agent_result.get(
            "severity_justification", ""
        )
        message["recommended_action"] = agent_result.get(
            "recommended_action", "flag_for_review"
        )
        message["attack_techniques"] = agent_result.get("attack_techniques", [])
        message["agent_latency_seconds"] = round(agent_time, 2)

        # IP enrichment (use real source IP from honeypot connection)
        try:
            enrichment_data = await enrich_ip(raw, real_ip=hp_meta.get("src_ip"))
            message["ip_enrichment"] = enrichment_data
        except Exception as enrich_exc:
            print(f"  [honeypot] Enrichment error: {enrich_exc}")
            message["ip_enrichment"] = None

        # Phase 17: formula-based risk score (honeypot source gets max bump)
        risk = calculate_risk_score(message)
        message["risk_score"]          = risk["risk_score"]
        message["risk_classification"] = risk["risk_classification"]
        message["risk_signals"]        = risk["risk_signals"]

        # Store and broadcast
        event_id = await _store_event(message.copy())
        message["event_id"] = event_id
        message["status"] = "pending_review"

        # Log honeypot connection to JSON-lines file and trigger CSV export
        try:
            hp_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_id": event_id,
                "event_type": "honeypot_probe",
                "src_ip": hp_meta.get("src_ip"),
                "src_port": hp_meta.get("src_port"),
                "dst_port": hp_meta.get("dst_port"),
                "probe_text": hp_meta.get("probe_text"),
                "probe_bytes_len": hp_meta.get("probe_bytes_len"),
                "connection_id": hp_meta.get("connection_id"),
                "severity": message.get("severity"),
                "risk_score": message.get("risk_score"),
                "recommended_action": message.get("recommended_action"),
                "triage": message.get("triage"),
            }
            append_honeypot_log(hp_record)
            asyncio.create_task(asyncio.to_thread(export_honeypot_csv))
        except Exception as csv_exc:
            logger.error("Honeypot CSV auto-export error: %s", csv_exc)

        conn_id = hp_meta.get("connection_id", "?")
        src = hp_meta.get("src_ip", "?")
        probe = hp_meta.get("probe_text", "")[:40]
        print(
            f"  [honeypot] #{conn_id} {src} -> triage complete "
            f"severity={message['severity']} risk={risk['risk_score']} {risk['risk_classification']} "
            f"probe={repr(probe)} [{event_id}]"
        )

    except Exception as exc:
        try:
            from pipeline import heuristic_triage
            fb = heuristic_triage(raw)
            message["triage"] = f"Honeypot probe on port {hp_meta.get('dst_port', 0)}. {fb['triage']}"
            message["severity"] = "High" if fb["severity"] in ("Critical", "High") else "Medium"
            message["severity_justification"] = fb["severity_justification"]
            message["recommended_action"] = "block_ip"
        except Exception:
            message["triage"] = f"Honeypot probe detected on port {hp_meta.get('dst_port', 0)}."
            message["severity"] = "High"
            message["severity_justification"] = f"Honeypot probe detection (Agent error: {exc})"
            message["recommended_action"] = "block_ip"

        message["attack_techniques"] = []
        message["ip_enrichment"] = None
        message["agent_latency_seconds"] = 0
        risk = calculate_risk_score(message)
        message["risk_score"]          = risk["risk_score"]
        message["risk_classification"] = risk["risk_classification"]
        message["risk_signals"]        = risk["risk_signals"]
        event_id = await _store_event(message.copy())
        message["event_id"] = event_id
        message["status"] = "pending_review"

        # Log honeypot fallback event to JSON-lines file and trigger CSV export
        try:
            hp_record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_id": event_id,
                "event_type": "honeypot_probe",
                "src_ip": hp_meta.get("src_ip"),
                "src_port": hp_meta.get("src_port"),
                "dst_port": hp_meta.get("dst_port"),
                "probe_text": hp_meta.get("probe_text"),
                "probe_bytes_len": hp_meta.get("probe_bytes_len"),
                "connection_id": hp_meta.get("connection_id"),
                "severity": message.get("severity"),
                "risk_score": message.get("risk_score"),
                "recommended_action": message.get("recommended_action"),
                "triage": message.get("triage"),
            }
            append_honeypot_log(hp_record)
            asyncio.create_task(asyncio.to_thread(export_honeypot_csv))
        except Exception as csv_exc:
            logger.error("Honeypot fallback CSV auto-export error: %s", csv_exc)

        print(f"  [honeypot] Agent pipeline fallback used ({exc}) [{event_id}]")

    await _broadcast(message)


@app.get("/honeypot/start")
async def honeypot_start(
    port: int = 8899,
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Start the honeypot listener on localhost (RESEARCH_MODE only)."""
    _require_research_mode()
    global _honeypot

    try:
        if _honeypot and _honeypot.running:
            return {
                "status": "already_running",
                "port": _honeypot.port,
                "connections": _honeypot.connection_count,
            }

        _honeypot = HoneypotListener(
            host="127.0.0.1",
            port=port,
            on_connection=_honeypot_on_connection,
        )

        await _honeypot.start()
        return {"status": "started", "host": "127.0.0.1", "port": port}
    except HTTPException:
        raise
    except OSError as exc:
        return {"status": "error", "detail": str(exc)}
    except Exception as exc:
        logger.error("Honeypot start error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to start honeypot: {exc}")


@app.get("/honeypot/stop")
async def honeypot_stop(
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Stop the honeypot listener (RESEARCH_MODE only)."""
    _require_research_mode()
    global _honeypot

    try:
        if not _honeypot or not _honeypot.running:
            return {"status": "not_running"}

        connections = _honeypot.connection_count
        await _honeypot.stop()
        _honeypot = None
        return {"status": "stopped", "total_connections": connections}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Honeypot stop error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to stop honeypot: {exc}")


@app.get("/honeypot/status")
async def honeypot_status(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Check the honeypot listener status."""
    try:
        if _honeypot and _honeypot.running:
            return {
                "status": "running",
                "host": _honeypot.host,
                "port": _honeypot.port,
                "connections": _honeypot.connection_count,
            }
        return {"status": "stopped"}
    except Exception as exc:
        logger.error("Honeypot status error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to check honeypot status: {exc}")


# ---------------------------------------------------------------------------
# Suricata IDS (Phase 22)
# ---------------------------------------------------------------------------

_suricata: SuricataIngestor | None = None


async def _suricata_on_alert(event: dict) -> None:
    """Callback fired for each Suricata alert.

    Suricata signature matches are positive detections by definition.
    We skip the ML detection step (the signature IS the detection signal)
    and go straight to the agent triage pipeline — identical to honeypot.
    """
    suricata_meta = event.get("suricata_meta", {})
    network_meta = event.get("network_meta", {})
    raw = event.get("raw_event", {})

    # Run YARA signatures (some may also fire on Suricata events)
    sig_matches = match_signatures(raw)

    message: dict[str, Any] = {
        "event_index": event.get("event_index", 0),
        "raw_event": raw,
        "prediction": event.get("prediction", "suricata_alert"),
        "confidence": event.get("confidence", 1.0),
        "source": "suricata",
        "suricata_meta": suricata_meta,
        "network_meta": network_meta,
        "signature_matches": sig_matches,
        "ml_flagged": False,   # ML was not run
        "sig_flagged": len(sig_matches) > 0,
    }

    # Run agent triage pipeline (always — Suricata alert = always suspicious)
    try:
        from pipeline import run_pipeline  # noqa: F811

        t0 = time_module.perf_counter()
        agent_result = await asyncio.to_thread(run_pipeline, raw)
        agent_time = time_module.perf_counter() - t0

        message["triage"] = agent_result.get("triage", "")
        message["severity"] = agent_result.get("severity", suricata_meta.get("severity_label", "UNKNOWN"))
        message["severity_justification"] = agent_result.get(
            "severity_justification", ""
        )
        message["recommended_action"] = agent_result.get(
            "recommended_action", "flag_for_review"
        )
        message["attack_techniques"] = agent_result.get("attack_techniques", [])
        message["agent_latency_seconds"] = round(agent_time, 2)

        # IP enrichment (use real source IP from Suricata alert)
        try:
            enrichment_data = await enrich_ip(raw, real_ip=network_meta.get("src_ip"))
            message["ip_enrichment"] = enrichment_data
        except Exception as enrich_exc:
            print(f"  [suricata] Enrichment error: {enrich_exc}")
            message["ip_enrichment"] = None

        # Formula-based risk score
        risk = calculate_risk_score(message)
        message["risk_score"]          = risk["risk_score"]
        message["risk_classification"] = risk["risk_classification"]
        message["risk_signals"]        = risk["risk_signals"]

        # Store and broadcast
        event_id = await _store_event(message.copy())
        message["event_id"] = event_id
        message["status"] = "pending_review"

        # Auto-trigger Suricata CSV conversion
        try:
            asyncio.create_task(asyncio.to_thread(export_suricata_csv))
        except Exception as csv_exc:
            logger.error("Suricata CSV auto-export error: %s", csv_exc)

        sig_name = suricata_meta.get("signature", "?")
        src = network_meta.get("src_ip", "?")
        print(
            f"  [suricata] Alert #{event.get('event_index', '?')} {src} -> triage complete "
            f"severity={message['severity']} risk={risk['risk_score']} {risk['risk_classification']} "
            f"sig={sig_name} [{event_id}]"
        )

    except Exception as exc:
        suricata_sev = suricata_meta.get("severity_label", "Medium")
        try:
            from pipeline import heuristic_triage
            fb = heuristic_triage(raw)
            message["triage"] = f"Suricata IDS alert: {suricata_meta.get('signature', 'Unknown')}. {fb['triage']}"
            message["severity"] = suricata_sev if suricata_sev != "UNKNOWN" else fb["severity"]
            message["severity_justification"] = fb["severity_justification"]
            message["recommended_action"] = "block_ip" if message["severity"] in ("Critical", "High") else "flag_for_review"
        except Exception:
            message["triage"] = f"Suricata IDS alert: {suricata_meta.get('signature', 'Unknown')}"
            message["severity"] = suricata_sev if suricata_sev != "UNKNOWN" else "Medium"
            message["severity_justification"] = f"Suricata IDS detection (Agent error: {exc})"
            message["recommended_action"] = "flag_for_review"

        message["attack_techniques"] = []
        message["ip_enrichment"] = None
        message["agent_latency_seconds"] = 0
        risk = calculate_risk_score(message)
        message["risk_score"]          = risk["risk_score"]
        message["risk_classification"] = risk["risk_classification"]
        message["risk_signals"]        = risk["risk_signals"]
        event_id = await _store_event(message.copy())
        message["event_id"] = event_id
        message["status"] = "pending_review"
        print(f"  [suricata] Agent pipeline fallback used ({exc}) [{event_id}]")

    await _broadcast(message)


@app.get("/interfaces")
async def get_network_interfaces(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """List available network interfaces for live packet capture (excluding Bluetooth)."""
    try:
        ifaces = detect_interfaces()
        default_iface = get_default_interface()
        return {
            "interfaces": ifaces,
            "default": default_iface["name"] if default_iface else None,
        }
    except Exception as exc:
        logger.error("Interface detection error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to detect network interfaces: {exc}")


@app.get("/suricata/start")
async def suricata_start(
    interface: str | None = None,
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Start Suricata IDS on a local interface (RESEARCH_MODE only)."""
    _require_research_mode()
    global _suricata

    try:
        if _suricata and _suricata.running:
            return {
                "status": "already_running",
                "interface": _suricata.interface,
                "alerts": _suricata.alert_count,
                "events_per_minute": _suricata.events_per_minute,
            }

        # Resolve interface: if not supplied or 127.0.0.1, auto-detect default interface
        target_iface = (interface or "").strip()
        if not target_iface or target_iface == "127.0.0.1":
            default_info = get_default_interface()
            if default_info and default_info.get("name"):
                target_iface = default_info["name"]
            elif not target_iface:
                target_iface = "127.0.0.1"

        _suricata = SuricataIngestor(
            interface=target_iface,
            on_alert=_suricata_on_alert,
        )

        result = await _suricata.start()
        result["interface"] = target_iface
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Suricata start error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to start Suricata: {exc}")


@app.get("/suricata/stop")
async def suricata_stop(
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Stop the Suricata IDS engine (RESEARCH_MODE only)."""
    _require_research_mode()
    global _suricata

    try:
        if not _suricata or not _suricata.running:
            return {"status": "not_running"}

        result = await _suricata.stop()
        _suricata = None
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Suricata stop error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to stop Suricata: {exc}")


@app.get("/suricata/status")
async def suricata_status(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Check the Suricata IDS engine status."""
    try:
        if _suricata and _suricata.running:
            return {
                "status": "running",
                "interface": _suricata.interface,
                "alerts": _suricata.alert_count,
                "events_per_minute": _suricata.events_per_minute,
                "uptime_seconds": _suricata.uptime_seconds,
                "eve_json": str(_suricata.eve_json_path),
            }
        return {
            "status": "stopped",
            "interface": None,
            "alerts": 0,
            "events_per_minute": 0.0,
            "uptime_seconds": 0.0,
        }
    except Exception as exc:
        logger.error("Suricata status error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to check Suricata status: {exc}")


# ---------------------------------------------------------------------------
# Live Network Traffic Capture (Phase 24)
# ---------------------------------------------------------------------------

from network_monitor import LiveNetworkMonitor, get_available_interfaces as _get_live_interfaces

_live_monitor: LiveNetworkMonitor | None = None


async def _live_capture_on_event(event: dict) -> None:
    """Callback fired for each completed connection from live capture.

    Runs the full detection pipeline:
      1. XGBoost ML classification
      2. YARA signature matching
      3. If anomaly detected → LLM agent triage → Risk scoring → Dashboard
    """
    meta = event.pop("_meta", {})
    raw = event  # NSL-KDD-shaped features

    # Step 1: ML Inference
    try:
        payload = {}
        for col in FEATURE_COLS:
            if col in CATEGORICAL_COLS:
                payload[col] = str(raw.get(col, "other"))
            else:
                payload[col] = float(raw.get(col, 0))

        net_event = NetworkEvent(**payload)
        prediction, confidence = run_inference(net_event)
    except Exception as exc:
        prediction = "error"
        confidence = 0.0
        print(f"  [live-capture] ML inference error: {exc}")

    # Step 2: YARA Signature matching
    sig_matches = match_signatures(raw)
    ml_flagged = prediction == "anomaly"
    sig_flagged = len(sig_matches) > 0
    should_triage = ml_flagged or sig_flagged

    if should_triage and _live_monitor:
        _live_monitor._anomaly_count += 1

    # Build message
    raw_event_index = raw.get("event_index", 0)
    event_idx = int(raw_event_index) if raw_event_index else int(meta.get("capture_time", 0))

    message: dict[str, Any] = {
        "event_index": event_idx,
        "raw_event": raw,
        "prediction": prediction,
        "confidence": confidence,
        "source": "live_capture",
        "network_meta": {
            "src_ip": meta.get("src_ip", "unknown"),
            "src_port": meta.get("src_port", 0),
            "dst_ip": meta.get("dst_ip", "unknown"),
            "dst_port": meta.get("dst_port", 0),
            "proto": str(raw.get("protocol_type", "tcp")),
            "packets": meta.get("packets", 1),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "signature_matches": sig_matches,
        "ml_flagged": ml_flagged,
        "sig_flagged": sig_flagged,
    }

    if should_triage:
        trigger = "ml+sig" if (ml_flagged and sig_flagged) else ("ml" if ml_flagged else "sig")
        try:
            from pipeline import run_pipeline  # noqa: F811

            t0 = time_module.perf_counter()
            agent_result = await asyncio.to_thread(run_pipeline, raw)
            agent_time = time_module.perf_counter() - t0

            message["triage"] = agent_result.get("triage", "")
            message["severity"] = agent_result.get("severity", "UNKNOWN")
            message["severity_justification"] = agent_result.get(
                "severity_justification", ""
            )
            message["recommended_action"] = agent_result.get(
                "recommended_action", "flag_for_review"
            )
            message["attack_techniques"] = agent_result.get("attack_techniques", [])
            message["agent_latency_seconds"] = round(agent_time, 2)

            # IP enrichment (real IPs from live capture)
            try:
                enrichment_data = await enrich_ip(raw, real_ip=meta.get("src_ip"))
                message["ip_enrichment"] = enrichment_data
            except Exception as enrich_exc:
                print(f"  [live-capture] Enrichment error: {enrich_exc}")
                message["ip_enrichment"] = None

            # Risk score
            risk = calculate_risk_score(message)
            message["risk_score"]          = risk["risk_score"]
            message["risk_classification"] = risk["risk_classification"]
            message["risk_signals"]        = risk["risk_signals"]

            # Store and broadcast
            event_id = await _store_event(message.copy())
            message["event_id"] = event_id
            message["status"] = "pending_review"

            src = meta.get("src_ip", "?")
            dst = meta.get("dst_ip", "?")
            dst_port = meta.get("dst_port", 0)
            print(
                f"  [live-capture] FLAGGED ({trigger}) {src} -> {dst}:{dst_port} "
                f"severity={message['severity']} risk={risk['risk_score']} "
                f"{risk['risk_classification']} [{event_id}]"
            )

        except Exception as exc:
            try:
                from pipeline import heuristic_triage
                fb = heuristic_triage(raw)
                message["triage"] = fb["triage"]
                message["severity"] = fb["severity"]
                message["severity_justification"] = fb["severity_justification"]
                message["recommended_action"] = fb["recommended_action"]
            except Exception:
                message["triage"] = "Live traffic anomaly detected requiring analyst review."
                message["severity"] = "Medium"
                message["severity_justification"] = f"Fallback triage (Agent error: {exc})"
                message["recommended_action"] = "flag_for_review"

            message["attack_techniques"] = []
            message["ip_enrichment"] = None
            message["agent_latency_seconds"] = 0
            risk = calculate_risk_score(message)
            message["risk_score"]          = risk["risk_score"]
            message["risk_classification"] = risk["risk_classification"]
            message["risk_signals"]        = risk["risk_signals"]
            event_id = await _store_event(message.copy())
            message["event_id"] = event_id
            message["status"] = "pending_review"
            print(f"  [live-capture] Agent fallback ({exc}) [{event_id}]")
    else:
        message["event_id"] = None
        message["status"] = None

    await _broadcast(message)


@app.get("/live/interfaces")
async def live_get_interfaces(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """List available network interfaces for live traffic capture."""
    try:
        interfaces = _get_live_interfaces()
        default_iface = None
        for iface in interfaces:
            if iface.get("is_up") and iface.get("ip"):
                default_iface = iface.get("name")
                break
        if not default_iface and interfaces:
            default_iface = interfaces[0].get("name")
        return {
            "interfaces": interfaces,
            "count": len(interfaces),
            "default": default_iface,
        }
    except Exception as exc:
        logger.error("Interface detection error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to detect interfaces: {exc}")


@app.get("/live/start")
@app.post("/live/start")
async def live_start(
    interface: str = "Wi-Fi",
    packet_limit: int = 0,
    time_limit: int = 0,
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Start live network traffic capture on a WiFi/Ethernet interface.

    Parameters:
        interface: Interface name ('Wi-Fi', 'Ethernet') or GUID
        packet_limit: Max packets before auto-stop (0 = unlimited)
        time_limit: Max seconds before auto-stop (0 = unlimited)
    """
    global _live_monitor

    try:
        if _live_monitor and _live_monitor.running:
            return {"status": "already_running", **_live_monitor.stats}

        _live_monitor = LiveNetworkMonitor(
            interface=interface,
            on_event=_live_capture_on_event,
            packet_limit=packet_limit,
            time_limit=time_limit,
        )

        result = await _live_monitor.start()
        result["started_by"] = current_user["username"]
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Live capture start error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to start live capture: {exc}")


@app.get("/live/stop")
@app.post("/live/stop")
async def live_stop(
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Stop live network traffic capture."""
    global _live_monitor

    try:
        if not _live_monitor or not _live_monitor.running:
            return {"status": "not_running"}

        result = await _live_monitor.stop()
        result["stopped_by"] = current_user["username"]
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Live capture stop error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to stop live capture: {exc}")


@app.get("/live/status")
async def live_status(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Check live network traffic capture status."""
    try:
        if _live_monitor and _live_monitor.running:
            return {"status": "running", **_live_monitor.stats}
        return {
            "status": "stopped",
            "running": False,
            "interface": None,
            "events_processed": 0,
            "anomalies_detected": 0,
        }
    except Exception as exc:
        logger.error("Live capture status error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to check live capture status: {exc}")


# ---------------------------------------------------------------------------
# CSV Log Export Endpoints (Phase 23)
# ---------------------------------------------------------------------------

@app.get("/logs/export/csv/{source}")
async def export_csv(
    source: str,
    regenerate: bool = True,
    current_user: dict = Depends(require_role("admin")),
) -> FileResponse:
    """Export Suricata eve.json alerts or honeypot logs to Excel-compatible CSV.

    Parameters:
      source: 'suricata' or 'honeypot'
      regenerate: whether to trigger fresh conversion (default True)
    """
    src = source.lower().strip()
    if src not in ("suricata", "honeypot"):
        raise HTTPException(
            status_code=400,
            detail="Invalid log source. Must be 'suricata' or 'honeypot'.",
        )

    try:
        if regenerate:
            if src == "suricata":
                csv_path = await asyncio.to_thread(export_suricata_csv)
            else:
                csv_path = await asyncio.to_thread(export_honeypot_csv)
        else:
            csv_path = get_latest_csv(src)
            if not csv_path:
                if src == "suricata":
                    csv_path = await asyncio.to_thread(export_suricata_csv)
                else:
                    csv_path = await asyncio.to_thread(export_honeypot_csv)

        if not csv_path or not csv_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"No {src} CSV file could be generated.",
            )

        return FileResponse(
            path=str(csv_path),
            media_type="text/csv",
            filename=csv_path.name,
            headers={"Content-Disposition": f'attachment; filename="{csv_path.name}"'},
        )
    except FileNotFoundError as fnf:
        logger.warning("CSV export file not found: %s", fnf)
        raise HTTPException(status_code=404, detail=str(fnf))
    except ValueError as ve:
        logger.warning("CSV export value error: %s", ve)
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        logger.error("CSV export error for %s: %s", src, exc)
        raise HTTPException(status_code=500, detail=f"CSV export failed: {exc}")


@app.get("/logs/download-csv")
async def download_csv_alias(
    source: str = "suricata",
    current_user: dict = Depends(require_role("admin")),
) -> FileResponse:
    """Convenience alias for downloading CSV by query parameter."""
    return await export_csv(source=source)


@app.get("/logs/csv/list")
async def list_csvs(
    current_user: dict = Depends(require_role("admin")),
) -> dict[str, Any]:
    """List all generated CSV files in data/csv/."""
    try:
        files = list_exported_csvs()
        return {"count": len(files), "files": files}
    except Exception as exc:
        logger.error("List CSVs error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to list CSV files: {exc}")


# ---------------------------------------------------------------------------
# Event approval / rejection endpoints (Phase 9)
# ---------------------------------------------------------------------------

@app.get("/events/pending")
async def events_pending(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """List all events still awaiting human review."""
    try:
        pending = await db.get_pending_events()
        return {"count": len(pending), "events": pending}
    except Exception as exc:
        logger.error("Events pending error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch pending events: {exc}")


@app.get("/events/history")
async def events_history(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Return resolved events (approved/rejected), most recent first."""
    try:
        history = await db.get_event_history(limit=limit)
        return {"count": len(history), "events": history}
    except Exception as exc:
        logger.error("Events history error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch event history: {exc}")


@app.get("/events/filter")
async def events_filter(
    status: str | None = None,
    llm_severity: str | None = None,
    risk_classification: str | None = None,
    source: str | None = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Filter stored events by status, LLM severity, risk classification, or source."""
    try:
        filtered = await db.get_filtered_events(
            status=status,
            llm_severity=llm_severity,
            risk_classification=risk_classification,
            source=source,
            limit=limit,
        )
        return {"count": len(filtered), "events": filtered}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Filter query error: {exc}")


@app.get("/events/{event_id}")
async def event_status(
    event_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Get the current status of a specific event."""
    try:
        ev = await db.get_event(event_id)
        if ev is None:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")
        return {"event_id": event_id, "status": ev.get("status"), "data": ev}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Event status error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch event: {exc}")


@app.post("/events/{event_id}/approve")
async def event_approve(
    event_id: str,
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Approve the recommended action for a pending event.

    Uses atomic findOneAndUpdate -- only updates if status is still
    'pending_review'. Returns 409 if already resolved (double-action guard).
    """
    try:
        existing = await db.get_event(event_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")

        updated = await db.approve_event(event_id, resolved_by=current_user["username"])
        if updated is None:
            raise HTTPException(
                status_code=409,
                detail=f"Event {event_id} already resolved as '{existing.get('status')}'. "
                       f"Cannot approve again.",
            )

        action = updated.get("recommended_action", "unknown")
        print(f"  [approval] Event {event_id} APPROVED by {current_user['username']}.")
        print(f"  [approval] SIMULATED: executing '{action}' "
              f"(severity={updated.get('severity', '?')})")

        await _broadcast({
            "type": "status_update",
            "event_id": event_id,
            "status": "approved",
            "action_executed": action,
            "resolved_by": current_user["username"],
        })

        return {
            "event_id": event_id,
            "status": "approved",
            "action_executed": action,
            "resolved_by": current_user["username"],
            "note": f"SIMULATED: '{action}' executed.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Event approve error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to approve event: {exc}")


@app.post("/events/{event_id}/reject")
async def event_reject(
    event_id: str,
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Reject the recommended action for a pending event.

    Uses atomic findOneAndUpdate -- same double-action guard as approve.
    """
    try:
        existing = await db.get_event(event_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")

        updated = await db.reject_event(event_id, resolved_by=current_user["username"])
        if updated is None:
            raise HTTPException(
                status_code=409,
                detail=f"Event {event_id} already resolved as '{existing.get('status')}'. "
                       f"Cannot reject again.",
            )

        action = updated.get("recommended_action", "unknown")
        print(f"  [approval] Event {event_id} REJECTED by {current_user['username']}. No action taken.")

        await _broadcast({
            "type": "status_update",
            "event_id": event_id,
            "status": "rejected",
            "action_declined": action,
            "resolved_by": current_user["username"],
        })

        return {
            "event_id": event_id,
            "status": "rejected",
            "action_declined": action,
            "resolved_by": current_user["username"],
            "note": "Action declined. No action was taken.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Event reject error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to reject event: {exc}")


# ---------------------------------------------------------------------------
# Phase 17: Extended SOC status transitions
# ---------------------------------------------------------------------------

@app.post("/events/{event_id}/investigate")
async def event_investigate(
    event_id: str,
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Mark an event as 'investigating'."""
    try:
        existing = await db.get_event(event_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")

        updated = await db.update_event_status(
            event_id, "investigating", updated_by=current_user["username"]
        )
        if updated is None:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")

        print(f"  [status] Event {event_id} -> INVESTIGATING by {current_user['username']}")

        await _broadcast({
            "type": "status_update",
            "event_id": event_id,
            "status": "investigating",
            "resolved_by": current_user["username"],
        })

        return {
            "event_id": event_id,
            "status": "investigating",
            "updated_by": current_user["username"],
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Event investigate error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to update event: {exc}")


@app.post("/events/{event_id}/false_positive")
async def event_false_positive(
    event_id: str,
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Mark an event as 'false_positive'."""
    try:
        existing = await db.get_event(event_id)
        if existing is None:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")

        updated = await db.update_event_status(
            event_id, "false_positive", updated_by=current_user["username"]
        )
        if updated is None:
            raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")

        print(f"  [status] Event {event_id} -> FALSE_POSITIVE by {current_user['username']}")

        await _broadcast({
            "type": "status_update",
            "event_id": event_id,
            "status": "false_positive",
            "resolved_by": current_user["username"],
        })

        return {
            "event_id": event_id,
            "status": "false_positive",
            "updated_by": current_user["username"],
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Event false_positive error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to update event: {exc}")


# ---------------------------------------------------------------------------
# Phase 17: Stats overview endpoint
# ---------------------------------------------------------------------------

@app.get("/stats/overview")
async def stats_overview(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Return aggregated event counts by severity, status, and detection source.

    Powers the dashboard summary panel. No auth required — read-only aggregate
    counts contain no sensitive event content.
    """
    try:
        return await db.get_stats_overview()
    except Exception:
        # MongoDB not connected or other error — return zeros gracefully
        return {
            "total_events": 0, "pending_review": 0, "investigating": 0,
            "false_positives": 0, "critical_severity": 0, "risk_critical": 0,
            "honeypot_sourced": 0, "by_status": {}, "by_llm_severity": {},
            "by_risk_class": {}, "by_source": {},
        }


# ---------------------------------------------------------------------------
# Dataset Upload & Schema Mapping Endpoints
# ---------------------------------------------------------------------------

@app.post("/dataset/upload")
async def dataset_upload(
    file: UploadFile = File(...),
    model_type: str = Form("xgboost"),
    max_rows: int = Form(100),
    current_user: dict = Depends(require_role("analyst")),
) -> dict:
    """Accept a CSV file, detect schema (NSL-KDD, CICIDS2017, UNSW-NB15),
    map features to the trained model's NSL-KDD schema, and run detection + triage pipeline."""
    if _model is None:
        raise HTTPException(status_code=503, detail="Detection models not loaded.")

    # ── Upload validation ─────────────────────────────────────────────
    MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

    # Check file extension
    filename = (file.filename or "").lower()
    if not filename.endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail=f"Only .csv files are accepted. Got: '{file.filename}'",
        )

    # Check content type (browsers send text/csv or application/vnd.ms-excel)
    allowed_types = {"text/csv", "application/vnd.ms-excel", "application/octet-stream"}
    if file.content_type and file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid content type '{file.content_type}'. Expected text/csv.",
        )

    # Read with size limit
    contents = await file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(contents) / 1024 / 1024:.1f} MB). "
                   f"Maximum allowed: {MAX_UPLOAD_BYTES / 1024 / 1024:.0f} MB.",
        )

    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        mapped_result = process_csv_upload(contents, max_rows=max_rows)
    except SchemaDetectionError as sde:
        return JSONResponse(status_code=400, content=sde.details)
    except Exception as exc:
        return JSONResponse(
            status_code=400,
            content={
                "error": "csv_processing_error",
                "detail": f"Failed to process CSV: {exc}",
            },
        )

    # Process rows through model + triage pipeline
    total_processed = len(mapped_result.df_mapped)
    anomalies_count = 0
    normal_count = 0
    triaged_count = 0
    alerts_generated: list[dict] = []

    is_unsw = getattr(mapped_result, "model_target", "") == "unsw_nb15_xgb"
    if is_unsw:
        model_label = "unsw_nb15_xgb"
    else:
        model_label = "Random Forest" if model_type.lower() in ("rf", "random_forest") else "XGBoost"

    display_df = getattr(mapped_result, "display_df", None)

    for idx, row in mapped_result.df_mapped.iterrows():
        row_dict = row.to_dict()
        display_row = display_df.iloc[idx].to_dict() if display_df is not None else {}
        srcip = display_row.get("srcip")
        dstip = display_row.get("dstip")
        sport = display_row.get("sport")
        dsport = display_row.get("dsport")
        attack_cat = display_row.get("attack_cat") or "Normal"

        # 1. Inference
        if is_unsw and _model_unsw is not None:
            try:
                row_df = pd.DataFrame([row_dict])
                pred = int(_model_unsw.predict(row_df)[0])
                prediction = "anomaly" if pred == 1 else "normal"
                proba = _model_unsw.predict_proba(row_df)[0]
                confidence = float(proba[pred])
            except Exception as exc:
                logger.error("UNSW inference error at row %d: %s", idx, exc)
                prediction = "error"
                confidence = 0.0
        else:
            try:
                event = NetworkEvent(**row_dict)
                prediction, confidence = run_inference(event, model_type=model_type)
            except Exception as exc:
                prediction = "error"
                confidence = 0.0

        # 2. Signature & Anomaly Flagging
        sig_matches = match_signatures(row_dict)
        ml_flagged = prediction == "anomaly"
        sig_flagged = len(sig_matches) > 0
        should_triage = ml_flagged or sig_flagged

        if ml_flagged:
            anomalies_count += 1
        else:
            normal_count += 1

        message: dict[str, Any] = {
            "event_index": idx,
            "raw_event": row_dict,
            "source_ip": str(srcip) if (srcip and pd.notna(srcip)) else None,
            "destination_ip": str(dstip) if (dstip and pd.notna(dstip)) else None,
            "source_port": sport if (sport and pd.notna(sport)) else None,
            "destination_port": dsport if (dsport and pd.notna(dsport)) else None,
            "attack_category": attack_cat,
            "prediction": prediction,
            "confidence": confidence,
            "source": "dataset_upload",
            "dataset_schema": mapped_result.schema_name,
            "model_used": model_label,
            "signature_matches": sig_matches,
            "ml_flagged": ml_flagged,
            "sig_flagged": sig_flagged,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if should_triage:
            triaged_count += 1
            real_ip_arg = str(srcip).strip() if (srcip and pd.notna(srcip)) else None
            ip_val = real_ip_arg or generate_simulated_ip(row_dict)
            if not message["source_ip"]:
                message["source_ip"] = ip_val
            message["ip_enrichment"] = {
                "ip": message["source_ip"],
                "ip_type": "real" if real_ip_arg else "simulated",
                "reputation": {"score": 0, "verdict": "batch_ingested", "source": "local_ingest"},
                "geolocation": {"country": "Unknown", "city": "Unknown", "source": "local_ingest"},
            }

            triage_ctx = row_dict.copy()
            if attack_cat and attack_cat != "Normal":
                triage_ctx["attack_category"] = attack_cat
            if message.get("source_ip"):
                triage_ctx["source_ip"] = message["source_ip"]

            # Fast deterministic heuristic triage for batch dataset ingestion
            try:
                from pipeline import heuristic_triage
                fb = heuristic_triage(triage_ctx)
                message["triage"] = fb.get("triage", "")
                message["severity"] = fb.get("severity", "Medium")
                message["severity_justification"] = fb.get("severity_justification", "")
                message["recommended_action"] = fb.get("recommended_action", "flag_for_review")
            except Exception as exc:
                msg_cat = f" {attack_cat}" if (attack_cat and attack_cat != "Normal") else ""
                message["triage"] = f"Anomalous{msg_cat} network activity detected from uploaded dataset."
                message["severity"] = "High" if attack_cat in ("Exploits", "Backdoors", "DoS", "Shellcode") else "Medium"
                message["severity_justification"] = f"Heuristic alert for{msg_cat} network activity ({exc})"
                message["recommended_action"] = "isolate_host" if attack_cat in ("Backdoors", "Exploits") else "flag_for_review"

            message["attack_techniques"] = []
            message["agent_latency_seconds"] = 0.0
            risk = calculate_risk_score(message)
            message["risk_score"] = risk["risk_score"]
            message["risk_classification"] = risk["risk_classification"]
            message["risk_signals"] = risk["risk_signals"]
            event_id = await _store_event(message.copy())
            message["event_id"] = event_id
            message["status"] = "pending_review"

            # Broadcast to WebSocket so live feed updates in real-time!
            await _broadcast(message)

            if len(alerts_generated) < 50:
                alerts_generated.append({
                    "event_id": message.get("event_id"),
                    "row_index": idx,
                    "source_ip": message.get("source_ip"),
                    "destination_ip": message.get("destination_ip"),
                    "source_port": message.get("source_port"),
                    "destination_port": message.get("destination_port"),
                    "attack_category": attack_cat,
                    "prediction": prediction,
                    "confidence": confidence,
                    "severity": message.get("severity"),
                    "risk_score": message.get("risk_score"),
                    "risk_classification": message.get("risk_classification"),
                    "recommended_action": message.get("recommended_action"),
                    "triage_summary": message.get("triage"),
                })
        else:
            message["event_id"] = None
            message["status"] = None
            # Broadcast normal events too so clients can see processing stream
            await _broadcast(message)

    return {
        "status": "success",
        "filename": file.filename or "dataset.csv",
        "schema": mapped_result.schema_name,
        "format_display": mapped_result.format_display,
        "model_used": model_label,
        "total_rows": mapped_result.total_rows,
        "processed_rows": total_processed,
        "anomalies_detected": anomalies_count,
        "normal_traffic": normal_count,
        "triaged_alerts": triaged_count,
        "columns_matched": mapped_result.columns_matched,
        "columns_defaulted": mapped_result.columns_defaulted,
        "alerts": alerts_generated,
    }


@app.get("/dataset/sample/{template_name}")
async def get_dataset_sample(template_name: str) -> Response:
    """Return a valid benchmark CSV for testing (nsl, cic, unsw, or invalid)."""
    csv_str = generate_sample_csv(template_name)
    return Response(
        content=csv_str,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{template_name}_sample.csv"'},
    )


# ---------------------------------------------------------------------------
# Authentication routes (Phase 16)
# ---------------------------------------------------------------------------

@app.post("/auth/register", status_code=201)
async def auth_register(req: RegisterRequest) -> dict:
    """Register a new analyst account."""
    try:
        return await register_user(req)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Auth register error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Registration failed: {exc}")


@app.post("/auth/login")
async def auth_login(req: LoginRequest):
    """Authenticate and return a JWT bearer token."""
    try:
        return await login_user(req)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Auth login error: %s", exc)
        raise HTTPException(status_code=500, detail=f"Login failed: {exc}")
