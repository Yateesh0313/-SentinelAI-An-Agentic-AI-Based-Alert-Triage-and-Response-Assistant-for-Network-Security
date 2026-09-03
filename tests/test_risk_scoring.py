"""Unit tests for the Risk Scoring Engine (Phase 17).

Tests:
- Deterministic formula output across known event archetypes
- Bounded output guarantee: score in [0, 100]
- Weight distribution validation (sum == 1.00)
- Classification threshold mapping:
    0-24: LOW, 25-49: MEDIUM, 50-74: HIGH, 75-100: CRITICAL
- Resilience to missing or malformed fields
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "backend"))

from risk_scoring import (
    calculate_risk_score,
    W_ML_CONFIDENCE,
    W_REPUTATION,
    W_SIGNATURE,
    W_ATTACK,
    W_SOURCE,
)


def test_weights_sum_to_one():
    """Validate that the five mathematical weights sum precisely to 1.0."""
    total = W_ML_CONFIDENCE + W_REPUTATION + W_SIGNATURE + W_ATTACK + W_SOURCE
    assert pytest.approx(total, abs=1e-6) == 1.0


def test_clean_normal_traffic():
    """Legitimate normal traffic must classify as LOW risk."""
    event = {
        "prediction": "normal",
        "confidence": 0.99,
        "source": "replay",
        "signature_matches": [],
        "attack_techniques": [],
        "ip_enrichment": None,
    }
    result = calculate_risk_score(event)
    assert 0 <= result["risk_score"] <= 24
    assert result["risk_classification"] == "LOW"
    assert result["risk_signals"]["ml_confidence"] <= 0.05


def test_ml_anomaly_moderate_threat():
    """Moderate ML anomaly without signature or reputation should classify as MEDIUM."""
    event = {
        "prediction": "anomaly",
        "confidence": 0.85,
        "source": "replay",
        "signature_matches": [],
        "attack_techniques": [],
        "ip_enrichment": None,
    }
    result = calculate_risk_score(event)
    assert 25 <= result["risk_score"] <= 49
    assert result["risk_classification"] == "MEDIUM"


def test_high_severity_anomaly_with_signature():
    """High-confidence anomaly with high YARA signature match should classify as HIGH."""
    event = {
        "prediction": "anomaly",
        "confidence": 0.98,
        "source": "replay",
        "signature_matches": [{"rule": "SYN_Flood_Pattern", "severity": "high"}],
        "attack_techniques": [{"id": "T1498", "name": "Network Denial of Service"}],
        "ip_enrichment": None,
    }
    result = calculate_risk_score(event)
    assert 50 <= result["risk_score"] <= 74
    assert result["risk_classification"] == "HIGH"


def test_critical_honeypot_with_reputation():
    """Honeypot hit with high AbuseIPDB score and critical technique must classify as CRITICAL."""
    event = {
        "prediction": "honeypot",
        "confidence": 1.0,
        "source": "honeypot",
        "signature_matches": [{"rule": "Telnet_Root_Access", "severity": "critical"}],
        "attack_techniques": [{"id": "T1110", "name": "Brute Force"}],
        "ip_enrichment": {
            "reputation": {
                "abuse_confidence_score": 95,
                "total_reports": 450,
            }
        },
    }
    result = calculate_risk_score(event)
    assert 75 <= result["risk_score"] <= 100
    assert result["risk_classification"] == "CRITICAL"


def test_edge_case_empty_and_nulls():
    """Empty or None payload must not raise an exception and should stay bounded."""
    result = calculate_risk_score({})
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_classification"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(result["risk_signals"], dict)
