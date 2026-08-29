"""SentinelAI — YARA Signature Matcher (Phase 13).

Serializes NSL-KDD event dicts into a text format that YARA can scan,
runs them against compiled rules, and returns matched rule names.

ARCHITECTURE NOTE — Hybrid detection:
    This module provides a SEPARATE, parallel detection layer alongside
    the ML-based anomaly detection (XGBoost from Phase 4).  The two methods
    can agree or disagree:
      - ML flags anomaly + signature matches  -> high confidence
      - ML flags anomaly, no signature match  -> novel/unknown pattern (ML strength)
      - ML says normal, signature matches     -> known-bad pattern ML missed
      - Neither flags                          -> likely benign

    This hybrid architecture mirrors real SOC practice: signatures catch
    known-bad patterns instantly, while ML catches novel threats.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yara

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_RULES_DIR = Path(__file__).resolve().parent
_RULES_FILE = _RULES_DIR / "rules.yar"

# ---------------------------------------------------------------------------
# Compiled rules (singleton, loaded once)
# ---------------------------------------------------------------------------

_compiled_rules: yara.Rules | None = None


def _load_rules() -> yara.Rules:
    """Compile and cache the YARA rules from rules.yar."""
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    if not _RULES_FILE.exists():
        raise FileNotFoundError(
            f"YARA rules file not found: {_RULES_FILE}\n"
            "Create ml/signatures/rules.yar first."
        )

    _compiled_rules = yara.compile(filepath=str(_RULES_FILE))
    print(f"  [signatures] Compiled YARA rules from {_RULES_FILE.name}")
    return _compiled_rules


# ---------------------------------------------------------------------------
# Event serialization
# ---------------------------------------------------------------------------

# Fields to include in the serialized text for YARA scanning.
# We include all fields that our rules reference, plus any that might be
# useful for future rules.
_SERIALIZE_FIELDS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]


def _serialize_event(event: dict[str, Any]) -> str:
    """Convert an event dict to a key=value text block for YARA scanning.

    Each field becomes a line like 'service=ftp' or 'src_bytes=12345'.
    YARA string/regex rules match against this text representation.
    """
    lines = []
    for field in _SERIALIZE_FIELDS:
        val = event.get(field)
        if val is not None:
            lines.append(f"{field}={val}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def match_signatures(event: dict[str, Any]) -> list[dict[str, str]]:
    """Run YARA rules against a serialized network event.

    Parameters
    ----------
    event : dict
        The raw NSL-KDD event dict (41 features).

    Returns
    -------
    list[dict]
        Each match is ``{"rule": "RuleName", "severity": "...", "description": "..."}``.
        Returns an empty list when no rules match.
    """
    try:
        rules = _load_rules()
    except Exception as exc:
        print(f"  [signatures] Failed to load YARA rules: {exc}")
        return []

    text = _serialize_event(event)

    try:
        matches = rules.match(data=text)
    except Exception as exc:
        print(f"  [signatures] YARA match error: {exc}")
        return []

    results: list[dict[str, str]] = []
    for m in matches:
        meta = m.meta if hasattr(m, "meta") else {}
        results.append({
            "rule": m.rule,
            "severity": meta.get("severity", "unknown"),
            "description": meta.get("description", ""),
        })

    return results
