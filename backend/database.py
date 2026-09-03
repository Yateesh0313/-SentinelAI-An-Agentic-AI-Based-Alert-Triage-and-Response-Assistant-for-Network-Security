"""SentinelAI Database Layer -- MongoDB persistence for events.

Provides async CRUD operations for the 'events' collection using motor.
Configured via MONGO_URI environment variable (defaults to localhost:27017).

Document shape:
{
    "event_id": str,
    "timestamp": str (ISO format),
    "raw_event": dict,
    "detection": {"prediction": str, "confidence": float, "ml_flagged": bool, "signature_flagged": bool},
    "triage": str,
    "severity": str,                     # LLM-assigned severity label
    "severity_justification": str,
    "recommended_action": str,
    "attack_techniques": [{"id": str, "name": str}, ...],
    "signature_matches": [{"rule": str, "severity": str, "description": str}, ...],
    "ip_enrichment": {"ip": str, "ip_type": str, "reputation": dict, "geolocation": dict},
    "risk_score": int (0-100),           # Phase 17: formula-based score
    "risk_classification": str,          # Phase 17: LOW|MEDIUM|HIGH|CRITICAL
    "risk_signals": dict,                # Phase 17: per-signal breakdown
    "status": "pending_review"|"investigating"|"false_positive"|"approved"|"rejected",
    "resolved_at": str | None,
    "resolved_by": str | None
}
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

# ---------------------------------------------------------------------------
# Connection configuration
# ---------------------------------------------------------------------------

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "sentinelai")

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def connect() -> AsyncIOMotorDatabase:
    """Connect to MongoDB and return the database handle."""
    global _client, _db
    if _db is not None:
        return _db

    print(f"  [db] Connecting to MongoDB at {MONGO_URI} ...")
    _client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)

    # Verify connection
    try:
        await _client.admin.command("ping")
        print("  [db] Connected to MongoDB successfully.")
    except Exception as exc:
        print(f"  [db] WARNING: MongoDB connection failed: {exc}")
        print("  [db] Events will NOT be persisted.")
        _client = None
        raise

    _db = _client[MONGO_DB_NAME]

    # Create index on event_id for fast lookups
    await _db.events.create_index("event_id", unique=True)
    # Index on status for pending queries
    await _db.events.create_index("status")
    # Index on resolved_at for history queries
    await _db.events.create_index("resolved_at")

    count = await _db.events.count_documents({})
    print(f"  [db] Database '{MONGO_DB_NAME}', collection 'events': {count} documents.")

    return _db


async def disconnect() -> None:
    """Close the MongoDB connection."""
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
        print("  [db] MongoDB connection closed.")


def _get_db() -> AsyncIOMotorDatabase:
    """Return the database handle (must call connect() first)."""
    if _db is None:
        raise RuntimeError("Database not connected. Call connect() first.")
    return _db


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------

async def insert_event(event_data: dict[str, Any], event_id: str) -> str:
    """Insert a new event document into the 'events' collection.

    Returns the event_id.
    """
    db = _get_db()

    doc = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_event": event_data.get("raw_event", {}),
        "detection": event_data.get("detection", {}),
        "triage": event_data.get("triage", ""),
        "severity": event_data.get("severity", "UNKNOWN"),
        "severity_justification": event_data.get("severity_justification", ""),
        "recommended_action": event_data.get("recommended_action", "flag_for_review"),
        "attack_techniques": event_data.get("attack_techniques", []),
        "signature_matches": event_data.get("signature_matches", []),
        "ip_enrichment": event_data.get("ip_enrichment"),
        # Phase 17: formula-based risk score (complements LLM severity)
        "risk_score": event_data.get("risk_score"),
        "risk_classification": event_data.get("risk_classification"),
        "risk_signals": event_data.get("risk_signals"),
        "status": "pending_review",
        "resolved_at": None,
        "resolved_by": None,
        "event_index": event_data.get("event_index"),
        "confidence": event_data.get("confidence"),
        "prediction": event_data.get("prediction"),
        "agent_latency_seconds": event_data.get("agent_latency_seconds"),
        "source": event_data.get("source"),
        "honeypot_meta": event_data.get("honeypot_meta"),
        "ml_flagged": event_data.get("ml_flagged"),
        "sig_flagged": event_data.get("sig_flagged"),
    }

    await db.events.insert_one(doc)
    return event_id


async def get_event(event_id: str) -> dict | None:
    """Fetch a single event by event_id."""
    db = _get_db()
    doc = await db.events.find_one({"event_id": event_id}, {"_id": 0})
    return doc


async def get_pending_events() -> list[dict]:
    """Fetch all events with status 'pending_review'."""
    db = _get_db()
    cursor = db.events.find(
        {"status": "pending_review"},
        {"_id": 0}
    ).sort("timestamp", -1)
    return await cursor.to_list(length=200)


async def get_event_history(limit: int = 50) -> list[dict]:
    """Fetch resolved events (approved/rejected/investigating/false_positive), most recent first."""
    db = _get_db()
    cursor = db.events.find(
        {"status": {"$in": ["approved", "rejected", "investigating", "false_positive"]}},
        {"_id": 0}
    ).sort("resolved_at", -1).limit(limit)
    return await cursor.to_list(length=limit)


async def approve_event(event_id: str, resolved_by: str = "analyst") -> dict | None:
    """Atomically approve an event only if it's still pending_review.

    Uses findOneAndUpdate with a status filter for the double-action guard.
    Returns the updated document, or None if already resolved / not found.
    """
    db = _get_db()
    result = await db.events.find_one_and_update(
        {"event_id": event_id, "status": "pending_review"},
        {
            "$set": {
                "status": "approved",
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "resolved_by": resolved_by,
            }
        },
        return_document=True,
        projection={"_id": 0},
    )
    return result


async def reject_event(event_id: str, resolved_by: str = "analyst") -> dict | None:
    """Atomically reject an event only if it's still pending_review.

    Same atomic guard as approve_event.
    Returns the updated document, or None if already resolved / not found.
    """
    db = _get_db()
    result = await db.events.find_one_and_update(
        {"event_id": event_id, "status": "pending_review"},
        {
            "$set": {
                "status": "rejected",
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "resolved_by": resolved_by,
            }
        },
        return_document=True,
        projection={"_id": 0},
    )
    return result


async def update_event_status(
    event_id: str,
    new_status: str,
    updated_by: str = "analyst",
) -> dict | None:
    """Set an event to 'investigating' or 'false_positive' — Phase 17 SOC lifecycle.

    Unlike approve/reject this does NOT require pending_review (an analyst
    can mark an already-investigating event as false_positive).
    Returns the updated document, or None if not found.
    """
    allowed = {"investigating", "false_positive", "approved", "rejected", "pending_review"}
    if new_status not in allowed:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {allowed}")

    db = _get_db()
    result = await db.events.find_one_and_update(
        {"event_id": event_id},
        {
            "$set": {
                "status": new_status,
                "resolved_at": datetime.now(timezone.utc).isoformat(),
                "resolved_by": updated_by,
            }
        },
        return_document=True,
        projection={"_id": 0},
    )
    return result


async def get_stats_overview() -> dict:
    """Aggregate event counts by severity, status, and source — Phase 17.

    Returns a summary dict suitable for the dashboard stats panel.
    Uses MongoDB aggregation pipelines for efficiency.
    """
    db = _get_db()
    total = await db.events.count_documents({})

    # By status
    status_pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]
    status_docs = await db.events.aggregate(status_pipeline).to_list(length=20)
    by_status = {d["_id"]: d["count"] for d in status_docs if d["_id"]}

    # By LLM severity
    severity_pipeline = [
        {"$match": {"severity": {"$ne": None}}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
    ]
    sev_docs = await db.events.aggregate(severity_pipeline).to_list(length=20)
    by_severity = {d["_id"]: d["count"] for d in sev_docs if d["_id"]}

    # By risk classification (formula-based)
    risk_pipeline = [
        {"$match": {"risk_classification": {"$ne": None}}},
        {"$group": {"_id": "$risk_classification", "count": {"$sum": 1}}},
    ]
    risk_docs = await db.events.aggregate(risk_pipeline).to_list(length=20)
    by_risk = {d["_id"]: d["count"] for d in risk_docs if d["_id"]}

    # By detection source
    source_pipeline = [
        {"$match": {"source": {"$ne": None}}},
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
    ]
    src_docs = await db.events.aggregate(source_pipeline).to_list(length=20)
    by_source = {d["_id"]: d["count"] for d in src_docs if d["_id"]}

    # Quick-access counters
    critical_count   = by_severity.get("Critical", 0)
    honeypot_count   = by_source.get("honeypot", 0)
    suricata_count   = by_source.get("suricata", 0)
    pending_count    = by_status.get("pending_review", 0)
    risk_critical    = by_risk.get("CRITICAL", 0)
    investigating    = by_status.get("investigating", 0)
    false_positives  = by_status.get("false_positive", 0)

    return {
        "total_events":       total,
        "pending_review":     pending_count,
        "investigating":      investigating,
        "false_positives":    false_positives,
        "critical_severity":  critical_count,
        "risk_critical":      risk_critical,
        "honeypot_sourced":   honeypot_count,
        "suricata_sourced":   suricata_count,
        "by_status":          by_status,
        "by_llm_severity":    by_severity,
        "by_risk_class":      by_risk,
        "by_source":          by_source,
    }


async def get_filtered_events(
    status: str | None = None,
    llm_severity: str | None = None,
    risk_classification: str | None = None,
    source: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """Fetch events matching any combination of filters — Phase 17 stats drill-down.

    All filters are ANDed together. Pass None to skip a filter.
    Special values:
      status='all'  → no status filter (return every event)
    """
    db = _get_db()
    query: dict = {}

    if status and status != "all":
        # pending_review maps to just that status
        query["status"] = status

    if llm_severity:
        query["severity"] = llm_severity

    if risk_classification:
        query["risk_classification"] = risk_classification

    if source:
        query["source"] = source

    cursor = db.events.find(query, {"_id": 0}).sort("timestamp", -1).limit(limit)
    return await cursor.to_list(length=limit)
