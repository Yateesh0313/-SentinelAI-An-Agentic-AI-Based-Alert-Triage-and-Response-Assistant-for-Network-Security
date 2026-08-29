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
import sys
import time as time_module
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from auth import (
    LoginRequest,
    RegisterRequest,
    get_current_user,
    login_user,
    register_user,
)

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
_scaler: Any = None
_encoder: Any = None


def _load_artifacts() -> None:
    """Load the trained model and preprocessing objects into module globals."""
    global _model, _scaler, _encoder

    model_path = _RESULTS_DIR / "classical_baseline_model.joblib"
    scaler_path = _PROCESSED_DIR / "scaler.joblib"
    encoder_path = _PROCESSED_DIR / "encoder.joblib"

    for p in [model_path, scaler_path, encoder_path]:
        if not p.exists():
            raise FileNotFoundError(
                f"Required artifact not found: {p}\n"
                "Run Phase 3 (loader) and Phase 4 (training) first."
            )

    _model = joblib.load(model_path)
    _scaler = joblib.load(scaler_path)
    _encoder = joblib.load(encoder_path)

    print(f"  [startup] Loaded model   : {model_path.name}")
    print(f"  [startup] Loaded scaler  : {scaler_path.name}")
    print(f"  [startup] Loaded encoder : {encoder_path.name}")


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
    version="0.10.0",
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
# Event store -- now backed by MongoDB (Phase 10)
# ---------------------------------------------------------------------------

import database as db
from enrichment import enrich_ip
from matcher import match_signatures
from listener import HoneypotListener
from risk_scoring import calculate_risk_score


async def _store_event(event_data: dict[str, Any]) -> str:
    """Assign a unique event_id, persist to MongoDB, return the id."""
    event_id = str(uuid.uuid4())[:8]
    await db.insert_event(event_data, event_id)
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

def run_inference(event: NetworkEvent) -> tuple[str, float]:
    """Preprocess a raw event and run the loaded model.

    Uses the SAME scaler/encoder from Phase 3 to guarantee consistency
    with Phase 4 training.

    Returns (prediction_label, confidence_score).
    """
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
    pred = _model.predict(X)[0]
    label = "anomaly" if pred == 1 else "normal"

    # Confidence from predict_proba
    proba = _model.predict_proba(X)[0]
    confidence = float(proba[pred])

    return label, round(confidence, 4)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def root() -> dict:
    """Root endpoint — API overview."""
    return {
        "app": "SentinelAI Backend",
        "version": "0.17.0",
        "status": "running",
        "endpoints": {
            "GET /": "This overview",
            "POST /detect": "Classify a single network event (ML + signatures)",
            "POST /triage": "Detect + full agent pipeline if flagged",
            "GET /replay/start": "Start streaming KDDTest+ events via WebSocket",
            "GET /replay/stop": "Stop the replay stream",
            "GET /honeypot/start": "Start the honeypot listener",
            "GET /honeypot/stop": "Stop the honeypot listener",
            "GET /honeypot/status": "Check honeypot listener status",
            "POST /events/{id}/approve": "Approve a pending event",
            "POST /events/{id}/reject": "Reject a pending event",
            "POST /events/{id}/investigate": "Mark event as investigating",
            "POST /events/{id}/false_positive": "Mark event as false positive",
            "GET /stats/overview": "Aggregated counts by severity/status/source",
            "WS /ws": "WebSocket for live event stream",
            "GET /docs": "Interactive API docs (Swagger UI)",
        },
    }


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return a simple health-check JSON response."""
    return HealthResponse(status="ok")


@app.post("/detect", response_model=DetectResponse)
async def detect(event: NetworkEvent) -> DetectResponse:
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
    raw = event.model_dump()
    sig_matches = match_signatures(raw)

    return DetectResponse(
        prediction=label,
        confidence=confidence,
        signature_matches=sig_matches,
        raw_event=raw,
    )


@app.post("/triage")
async def triage(event: NetworkEvent) -> dict:
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
    sig_matches = match_signatures(raw)
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
            result["triage"] = ""
            result["severity"] = "UNKNOWN"
            result["severity_justification"] = f"Agent error: {exc}"
            result["recommended_action"] = "flag_for_review"
            result["attack_techniques"] = []
            result["ip_enrichment"] = None
            result["agent_latency_seconds"] = 0
            # Still compute risk score from available signals
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
            print(f"  [triage] Agent pipeline error: {exc} [{event_id}]")
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
                message["triage"] = f"Agent error: {exc}"
                message["severity"] = "UNKNOWN"
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
                print(f"  [replay] #{idx} Agent pipeline error: {exc} [{event_id}]")
        else:
            message["event_id"] = None
            message["status"] = None
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
    """WebSocket endpoint for live event streaming."""
    await websocket.accept()
    _ws_clients.append(websocket)
    print(f"  [ws] Client connected. Total: {len(_ws_clients)}")
    try:
        while True:
            # Keep connection alive; ignore incoming messages
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)
        print(f"  [ws] Client disconnected. Total: {len(_ws_clients)}")


@app.get("/replay/start")
async def replay_start(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Start replaying KDDTest+ events over WebSocket at 1 event/sec."""
    global _replay_running, _replay_task

    if _replay_running:
        return {"status": "already_running"}

    _replay_running = True
    _replay_task = asyncio.create_task(_replay_loop())
    return {"status": "started", "started_by": current_user["username"]}


@app.get("/replay/stop")
async def replay_stop(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Stop the replay stream."""
    global _replay_running, _replay_task

    if not _replay_running:
        return {"status": "not_running"}

    _replay_running = False
    if _replay_task:
        _replay_task.cancel()
        _replay_task = None
    return {"status": "stopped", "stopped_by": current_user["username"]}


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

        # IP enrichment
        try:
            enrichment_data = await enrich_ip(raw)
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

        conn_id = hp_meta.get("connection_id", "?")
        src = hp_meta.get("src_ip", "?")
        probe = hp_meta.get("probe_text", "")[:40]
        print(
            f"  [honeypot] #{conn_id} {src} -> triage complete "
            f"severity={message['severity']} risk={risk['risk_score']} {risk['risk_classification']} "
            f"probe={repr(probe)} [{event_id}]"
        )

    except Exception as exc:
        message["triage"] = f"Agent error: {exc}"
        message["severity"] = "UNKNOWN"
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
        print(f"  [honeypot] Agent pipeline error: {exc} [{event_id}]")

    await _broadcast(message)


@app.get("/honeypot/start")
async def honeypot_start(
    port: int = 8899,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Start the honeypot listener on localhost."""
    global _honeypot

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

    try:
        await _honeypot.start()
        return {"status": "started", "host": "127.0.0.1", "port": port}
    except OSError as exc:
        return {"status": "error", "detail": str(exc)}


@app.get("/honeypot/stop")
async def honeypot_stop(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Stop the honeypot listener."""
    global _honeypot

    if not _honeypot or not _honeypot.running:
        return {"status": "not_running"}

    connections = _honeypot.connection_count
    await _honeypot.stop()
    _honeypot = None
    return {"status": "stopped", "total_connections": connections}


@app.get("/honeypot/status")
async def honeypot_status() -> dict:
    """Check the honeypot listener status."""
    if _honeypot and _honeypot.running:
        return {
            "status": "running",
            "host": _honeypot.host,
            "port": _honeypot.port,
            "connections": _honeypot.connection_count,
        }
    return {"status": "stopped"}


# ---------------------------------------------------------------------------
# Event approval / rejection endpoints (Phase 9)
# ---------------------------------------------------------------------------

@app.get("/events/pending")
async def events_pending() -> dict:
    """List all events still awaiting human review."""
    pending = await db.get_pending_events()
    return {"count": len(pending), "events": pending}


@app.get("/events/history")
async def events_history(limit: int = 50) -> dict:
    """Return resolved events (approved/rejected), most recent first."""
    history = await db.get_event_history(limit=limit)
    return {"count": len(history), "events": history}


@app.get("/events/filter")
async def events_filter(
    status: str | None = None,
    llm_severity: str | None = None,
    risk_classification: str | None = None,
    source: str | None = None,
    limit: int = 100,
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
async def event_status(event_id: str) -> dict:
    """Get the current status of a specific event."""
    ev = await db.get_event(event_id)
    if ev is None:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")
    return {"event_id": event_id, "status": ev.get("status"), "data": ev}


@app.post("/events/{event_id}/approve")
async def event_approve(
    event_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Approve the recommended action for a pending event.

    Uses atomic findOneAndUpdate -- only updates if status is still
    'pending_review'. Returns 409 if already resolved (double-action guard).
    """
    # Check if event exists first
    existing = await db.get_event(event_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")

    # Atomic approve (only if pending)
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

    # Broadcast status update to all WS clients
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


@app.post("/events/{event_id}/reject")
async def event_reject(
    event_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Reject the recommended action for a pending event.

    Uses atomic findOneAndUpdate -- same double-action guard as approve.
    """
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


# ---------------------------------------------------------------------------
# Phase 17: Extended SOC status transitions
# ---------------------------------------------------------------------------

@app.post("/events/{event_id}/investigate")
async def event_investigate(
    event_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Mark an event as 'investigating' — analyst is actively reviewing it.

    This is a richer SOC workflow state between pending_review and final
    resolution. Unlike approve/reject it does not require pending_review
    status, so an analyst can also move false_positive → investigating.
    """
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


@app.post("/events/{event_id}/false_positive")
async def event_false_positive(
    event_id: str,
    current_user: dict = Depends(get_current_user),
) -> dict:
    """Mark an event as 'false_positive' — analyst determined it's benign.

    Provides a dedicated false-positive state for audit and model feedback.
    Useful for measuring the FP rate of the detection pipeline.
    """
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


# ---------------------------------------------------------------------------
# Phase 17: Stats overview endpoint
# ---------------------------------------------------------------------------

@app.get("/stats/overview")
async def stats_overview() -> dict:
    """Return aggregated event counts by severity, status, and detection source.

    Powers the dashboard summary panel. No auth required — read-only aggregate
    counts contain no sensitive event content.
    """
    try:
        return await db.get_stats_overview()
    except RuntimeError:
        # MongoDB not connected — return zeros gracefully
        return {
            "total_events": 0, "pending_review": 0, "investigating": 0,
            "false_positives": 0, "critical_severity": 0, "risk_critical": 0,
            "honeypot_sourced": 0, "by_status": {}, "by_llm_severity": {},
            "by_risk_class": {}, "by_source": {},
        }


# ---------------------------------------------------------------------------
# Authentication routes (Phase 16)
# ---------------------------------------------------------------------------

@app.post("/auth/register", status_code=201)
async def auth_register(req: RegisterRequest) -> dict:
    """Register a new analyst account."""
    return await register_user(req)


@app.post("/auth/login")
async def auth_login(req: LoginRequest):
    """Authenticate and return a JWT bearer token."""
    return await login_user(req)
