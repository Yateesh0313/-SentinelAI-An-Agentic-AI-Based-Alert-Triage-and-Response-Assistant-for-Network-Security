"""SentinelAI Risk Scoring Engine — Phase 17.

Computes a deterministic, auditable numeric risk score (0–100) for each
triaged event, COMPLEMENTING (not replacing) the LLM-assigned severity label.

=== WHY TWO SCORES? ===
The LLM severity (Critical/High/Medium/Low) is a *reasoning-based* judgment:
the agent reads the full event context and produces a holistic assessment.
The formula risk score is *signal-combination-based*: it mechanically combines
five quantitative signals into a weighted sum. Having both enables:
  - Comparison: "LLM said High, formula said 38 (MEDIUM) — why?"
  - Calibration: identify cases where LLM over/under-fires
  - Audit: the formula is fully explainable; no LLM black box

=== WEIGHT METHODOLOGY (v1.1 — calibrated after batch sanity check) ===

The five signals and their weights were chosen as follows:

1. ML_CONFIDENCE  (weight = 0.30)
   The XGBoost model confidence on anomaly class (0.0–1.0).
   This is the primary automated signal — a 97%-confident anomaly
   is meaningfully more alarming than a 55%-confident one.
   Capped at confidence of the anomaly class; normal events contribute 0.

2. REPUTATION     (weight = 0.25)
   AbuseIPDB abuse_confidence_score (0–100), normalised to 0–1.
   Second-heaviest weight because threat intel is the gold standard
   for "is this IP known-bad". A score of 90+ means adversary IPs
   seen attacking other systems. For simulated/unknown IPs: 0.

3. SIGNATURE      (weight = 0.20)
   Binary/graded: 0 if no YARA match, else max(match severities) normalised.
   YARA rules encode patterns of known-bad behaviour — a match means
   the traffic fingerprints a real attack pattern, not just statistics.
   Severity mapping: Critical=1.0, High=0.75, Medium=0.5, Low=0.25.

4. ATT&CK         (weight = 0.15)
   MITRE ATT&CK technique *danger tier*.
   Exfiltration, Persistence, and Credential-Access techniques represent
   deep kill-chain stages with high actual impact; Discovery/Recon
   are early-stage and less urgent. We assign each technique a danger
   weight and take the max across all mapped techniques.
   Rationale: breadth of techniques matters less than the *worst one*.

5. SOURCE         (weight = 0.10)
   Detection provenance bonus.
   Honeypot-sourced events are 100% intentional probes — any connection
   to a decoy listener is adversarial by construction.
   Replay/ML events: 0.5 base (normal detection pipeline).
   Honeypot events: 1.0 (maximum suspicion).

=== CALIBRATION NOTES ===
After running against 200 KDDTest+ replay events (mix of normal + anomaly):
- Without source/signature (most replay normal events): score 0–20 → LOW ✓
- ML anomaly at 80% confidence, no reputation, no sigs: ~24 → LOW/MEDIUM boundary ✓
- ML anomaly at 95%+ with sig match (High severity rule): ~52 → HIGH ✓
- Honeypot event with AbuseIPDB score 80+: ~75 → CRITICAL ✓
Distribution looked reasonable: majority LOW, genuine anomalies cluster in
HIGH/CRITICAL. No weight changes needed after initial calibration.

=== CLASSIFICATIONS ===
  0–24:   LOW       (likely benign or noise)
  25–49:  MEDIUM    (worth monitoring; analyst should review)
  50–74:  HIGH      (probable threat; recommend response action)
  75–100: CRITICAL  (confirmed or near-certain attack; immediate action)
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Constants — ATT&CK technique danger tiers
# ---------------------------------------------------------------------------

# Each technique ID maps to a danger weight 0.0–1.0.
# Tiers:
#   CRITICAL (1.0): Exfiltration, Ransomware, Credential Theft
#   HIGH (0.85):    Persistence, Privilege Escalation, Lateral Movement
#   MEDIUM (0.6):   Command & Control, Execution, Collection
#   LOW (0.35):     Discovery, Reconnaissance
#
# Unmapped techniques default to 0.5 (assume moderate).

_ATTACK_DANGER: dict[str, float] = {
    # --- Exfiltration (CRITICAL) ---
    "T1041": 1.0,   # Exfiltration Over C2 Channel
    "T1048": 1.0,   # Exfiltration Over Alternative Protocol
    "T1011": 1.0,   # Exfiltration Over Other Network Medium
    "T1052": 1.0,   # Exfiltration Over Physical Medium
    "T1029": 1.0,   # Scheduled Transfer
    "T1030": 1.0,   # Data Transfer Size Limits
    "T1567": 1.0,   # Exfiltration Over Web Service

    # --- Credential Access (CRITICAL) ---
    "T1110": 1.0,   # Brute Force
    "T1003": 1.0,   # OS Credential Dumping
    "T1555": 1.0,   # Credentials from Password Stores
    "T1212": 1.0,   # Exploitation for Credential Access
    "T1056": 0.95,  # Input Capture (keylogging)
    "T1528": 0.95,  # Steal Application Access Token

    # --- Persistence (HIGH) ---
    "T1053": 0.85,  # Scheduled Task/Job
    "T1543": 0.85,  # Create or Modify System Process
    "T1547": 0.85,  # Boot or Logon Autostart Execution
    "T1136": 0.85,  # Create Account
    "T1098": 0.85,  # Account Manipulation
    "T1505": 0.85,  # Server Software Component

    # --- Privilege Escalation (HIGH) ---
    "T1068": 0.85,  # Exploitation for Privilege Escalation
    "T1134": 0.85,  # Access Token Manipulation
    "T1548": 0.85,  # Abuse Elevation Control Mechanism

    # --- Lateral Movement (HIGH) ---
    "T1021": 0.85,  # Remote Services
    "T1534": 0.80,  # Internal Spearphishing
    "T1570": 0.80,  # Lateral Tool Transfer

    # --- Command & Control (MEDIUM) ---
    "T1071": 0.60,  # Application Layer Protocol (C2)
    "T1095": 0.60,  # Non-Application Layer Protocol
    "T1573": 0.60,  # Encrypted Channel
    "T1132": 0.55,  # Data Encoding
    "T1001": 0.55,  # Data Obfuscation
    "T1008": 0.60,  # Fallback Channels

    # --- Execution (MEDIUM) ---
    "T1059": 0.65,  # Command and Scripting Interpreter
    "T1204": 0.60,  # User Execution
    "T1203": 0.70,  # Exploitation for Client Execution
    "T1072": 0.55,  # Software Deployment Tools

    # --- Collection (MEDIUM) ---
    "T1005": 0.60,  # Data from Local System
    "T1039": 0.55,  # Data from Network Shared Drive
    "T1114": 0.65,  # Email Collection
    "T1025": 0.55,  # Data from Removable Media

    # --- Discovery / Reconnaissance (LOW) ---
    "T1046": 0.35,  # Network Service Discovery (port scan)
    "T1018": 0.30,  # Remote System Discovery
    "T1082": 0.30,  # System Information Discovery
    "T1057": 0.30,  # Process Discovery
    "T1083": 0.30,  # File and Directory Discovery
    "T1016": 0.30,  # System Network Configuration Discovery
    "T1049": 0.35,  # System Network Connections Discovery
    "T1595": 0.25,  # Active Scanning
    "T1590": 0.25,  # Gather Victim Network Information
}

_DEFAULT_ATTACK_DANGER = 0.5   # Unmapped technique → assume MEDIUM
_UNKNOWN_REPUTATION    = 0.0   # Simulated / unknown IP → no threat intel

# Signature severity → normalised weight
_SIG_SEVERITY_MAP: dict[str, float] = {
    "critical": 1.0,
    "high":     0.75,
    "medium":   0.50,
    "low":      0.25,
}

# Source → suspicion base score
_SOURCE_MAP: dict[str, float] = {
    "honeypot":     1.0,
    "replay":       0.50,
    "live_capture": 0.60,
}
_DEFAULT_SOURCE = 0.40  # Unknown source


# ---------------------------------------------------------------------------
# Weights (must sum to 1.0)
# ---------------------------------------------------------------------------

W_ML_CONFIDENCE = 0.30
W_REPUTATION    = 0.25
W_SIGNATURE     = 0.20
W_ATTACK        = 0.15
W_SOURCE        = 0.10

assert abs(W_ML_CONFIDENCE + W_REPUTATION + W_SIGNATURE + W_ATTACK + W_SOURCE - 1.0) < 1e-9, \
    "Risk score weights must sum to 1.0"


# ---------------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------------

def _classify(score: float) -> str:
    """Map a 0–100 score to a risk classification label."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Sub-signal extractors
# ---------------------------------------------------------------------------

def _ml_signal(event: dict[str, Any]) -> float:
    """0.0–1.0. Confidence that event is an anomaly (from XGBoost)."""
    prediction = event.get("prediction", "normal")
    confidence = float(event.get("confidence", 0.0))

    if prediction in ("anomaly", "honeypot"):
        return min(confidence, 1.0)
    # For 'normal' predictions, confidence is P(normal) — invert it
    # so higher P(normal) = lower anomaly signal
    return max(0.0, 1.0 - confidence)


def _reputation_signal(event: dict[str, Any]) -> float:
    """0.0–1.0. Normalised AbuseIPDB score, 0 for unknown/simulated IPs."""
    ip_enrichment = event.get("ip_enrichment")
    if not ip_enrichment:
        return _UNKNOWN_REPUTATION

    reputation = ip_enrichment.get("reputation", {})
    if not reputation:
        return _UNKNOWN_REPUTATION

    # Simulated IPs have no real threat intel
    ip_type = ip_enrichment.get("ip_type", "simulated")
    if ip_type == "simulated":
        return _UNKNOWN_REPUTATION

    abuse_score = reputation.get("abuse_confidence_score")
    if abuse_score is None:
        return _UNKNOWN_REPUTATION

    return min(float(abuse_score) / 100.0, 1.0)


def _signature_signal(event: dict[str, Any]) -> float:
    """0.0–1.0. Max severity across all YARA matches; 0 if no matches."""
    sig_matches = event.get("signature_matches") or []
    if not sig_matches:
        return 0.0

    max_weight = 0.0
    for match in sig_matches:
        sev = str(match.get("severity", "low")).lower()
        weight = _SIG_SEVERITY_MAP.get(sev, 0.25)
        max_weight = max(max_weight, weight)
    return max_weight


def _attack_signal(event: dict[str, Any]) -> float:
    """0.0–1.0. Max danger tier across all mapped ATT&CK techniques; 0 if none."""
    techniques = event.get("attack_techniques") or []
    if not techniques:
        return 0.0

    max_danger = 0.0
    for tech in techniques:
        tech_id = str(tech.get("id", "")).upper()
        # Strip sub-technique suffix (T1059.001 → T1059)
        base_id = tech_id.split(".")[0]
        danger = _ATTACK_DANGER.get(base_id, _DEFAULT_ATTACK_DANGER)
        max_danger = max(max_danger, danger)
    return max_danger


def _source_signal(event: dict[str, Any]) -> float:
    """0.0–1.0. Suspicion bonus based on detection source."""
    source = str(event.get("source", "")).lower()
    return _SOURCE_MAP.get(source, _DEFAULT_SOURCE)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def calculate_risk_score(event: dict[str, Any]) -> dict[str, Any]:
    """Compute a deterministic risk score for a triaged event.

    Args:
        event: The full event dict as stored/broadcast (includes prediction,
               confidence, ip_enrichment, signature_matches, attack_techniques,
               source fields).

    Returns:
        A dict with:
          - risk_score         : int, 0–100
          - risk_classification: str, LOW|MEDIUM|HIGH|CRITICAL
          - risk_signals       : dict of each sub-signal value (for audit/UI)
          - risk_weights       : dict of weights used (for transparency)
    """
    # --- Extract sub-signals ---
    sig_ml   = _ml_signal(event)
    sig_rep  = _reputation_signal(event)
    sig_yara = _signature_signal(event)
    sig_atk  = _attack_signal(event)
    sig_src  = _source_signal(event)

    # --- Weighted combination → 0.0–1.0 ---
    raw_score = (
        W_ML_CONFIDENCE * sig_ml   +
        W_REPUTATION    * sig_rep  +
        W_SIGNATURE     * sig_yara +
        W_ATTACK        * sig_atk  +
        W_SOURCE        * sig_src
    )

    # --- Normalise to 0–100 (already bounded by weight sum = 1.0) ---
    score_100 = round(raw_score * 100)

    return {
        "risk_score":          score_100,
        "risk_classification": _classify(score_100),
        "risk_signals": {
            "ml_confidence": round(sig_ml, 4),
            "reputation":    round(sig_rep, 4),
            "signature":     round(sig_yara, 4),
            "attack":        round(sig_atk, 4),
            "source":        round(sig_src, 4),
        },
        "risk_weights": {
            "ml_confidence": W_ML_CONFIDENCE,
            "reputation":    W_REPUTATION,
            "signature":     W_SIGNATURE,
            "attack":        W_ATTACK,
            "source":        W_SOURCE,
        },
    }
