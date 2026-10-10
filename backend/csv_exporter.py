"""SentinelAI — CSV Log Export Service.

Integrates scripts/convert_logs_to_csv.py to convert Suricata eve.json
and honeypot JSON logs into clean, flat, Excel-readable CSV files.

Output files are stored in `/data/csv/` with timestamps:
  - suricata_alerts_<timestamp>.csv
  - honeypot_events_<timestamp>.csv
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
from typing import Any

# Ensure scripts directory is on sys.path to import convert_logs_to_csv
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS_DIR = _PROJECT_ROOT / "scripts"
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from convert_logs_to_csv import convert, flatten_json, load_jsonlines

logger = logging.getLogger("sentinel.csv_exporter")

CSV_DIR = _PROJECT_ROOT / "data" / "csv"
HONEYPOT_LOG_PATH = _PROJECT_ROOT / "data" / "honeypot_events.json"
SURICATA_LOG_FALLBACK = _PROJECT_ROOT / "data" / "eve.json"
DEFAULT_SURICATA_EVE = Path(r"C:\Users\User\suricata\log\sentinel\eve.json")


def ensure_dirs() -> None:
    """Ensure data/ and data/csv/ directories exist."""
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    HONEYPOT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)


def append_honeypot_log(event_record: dict[str, Any]) -> None:
    """Append a honeypot connection event to the JSON-lines honeypot log file."""
    ensure_dirs()
    try:
        with open(HONEYPOT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_record) + "\n")
    except Exception as exc:
        logger.error("Failed to append to honeypot log: %s", exc)


def get_latest_csv(source: str) -> Path | None:
    """Find the most recently created CSV file for a given source."""
    ensure_dirs()
    prefix = "suricata_alerts_" if source == "suricata" else "honeypot_events_"
    matches = sorted(
        CSV_DIR.glob(f"{prefix}*.csv"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    return matches[0] if matches else None


def list_exported_csvs() -> list[dict[str, Any]]:
    """List all generated CSV export files with metadata."""
    ensure_dirs()
    files = []
    for p in sorted(CSV_DIR.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True):
        files.append({
            "filename": p.name,
            "path": str(p),
            "size_bytes": p.stat().st_size,
            "created_at": datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc).isoformat(),
            "source": "suricata" if "suricata" in p.name else "honeypot",
        })
    return files


def _find_suricata_eve_path() -> Path | None:
    """Locate the best available eve.json log file."""
    # 1. Active Suricata sentinel log dir
    if DEFAULT_SURICATA_EVE.exists() and DEFAULT_SURICATA_EVE.stat().st_size > 0:
        return DEFAULT_SURICATA_EVE

    # 2. Project-level data/eve.json
    if SURICATA_LOG_FALLBACK.exists() and SURICATA_LOG_FALLBACK.stat().st_size > 0:
        return SURICATA_LOG_FALLBACK

    # 3. Known test eve.json directories from Suricata installation
    suricata_base = Path(r"C:\Users\User\suricata\log")
    if suricata_base.exists():
        for sub in ("ingest_test", "ingest_test2", "ingest_test3", "test", "nmap_test"):
            candidate = suricata_base / sub / "eve.json"
            if candidate.exists() and candidate.stat().st_size > 0:
                return candidate

    return None


def export_suricata_csv(input_path: Path | str | None = None) -> Path:
    """Convert Suricata eve.json to data/csv/suricata_alerts_<timestamp>.csv.

    Uses the exact conversion and flattening logic from scripts/convert_logs_to_csv.py.
    """
    ensure_dirs()
    in_path = Path(input_path) if input_path else _find_suricata_eve_path()

    if not in_path or not in_path.exists():
        raise FileNotFoundError(
            f"No Suricata eve.json log file found. Checked: {DEFAULT_SURICATA_EVE}, {SURICATA_LOG_FALLBACK}"
        )

    records = load_jsonlines(str(in_path))
    alert_records = [r for r in records if r.get("event_type") == "alert"]
    if not alert_records and not records:
        raise ValueError(f"No records found in Suricata log file: {in_path}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = CSV_DIR / f"suricata_alerts_{ts}.csv"

    # Invoke convert directly from convert_logs_to_csv
    convert(str(in_path), str(out_path), source="suricata", alerts_only=True)
    return out_path


def export_honeypot_csv(input_path: Path | str | None = None) -> Path:
    """Convert honeypot JSON logs to data/csv/honeypot_events_<timestamp>.csv.

    Uses the exact conversion and flattening logic from scripts/convert_logs_to_csv.py.
    """
    ensure_dirs()
    in_path = Path(input_path) if input_path else HONEYPOT_LOG_PATH

    if not in_path.exists() or in_path.stat().st_size == 0:
        raise FileNotFoundError(
            f"No honeypot log file found at {in_path}. Start the honeypot or generate connections first."
        )

    records = load_jsonlines(str(in_path))
    if not records:
        raise ValueError(f"No valid JSON records found in honeypot log file: {in_path}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = CSV_DIR / f"honeypot_events_{ts}.csv"

    convert(str(in_path), str(out_path), source="honeypot", alerts_only=False)
    return out_path
