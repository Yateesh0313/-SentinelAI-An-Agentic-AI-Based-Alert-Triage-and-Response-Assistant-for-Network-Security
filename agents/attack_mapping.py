"""SentinelAI — MITRE ATT&CK Technique Mapper (Phase 11).

This module maps raw NSL-KDD-style network events to MITRE ATT&CK technique
IDs using a small, hardcoded heuristic lookup table.

DESIGN DECISION — Rule-based, NOT learned:
    This layer is intentionally a deterministic rule engine, not an ML model
    or LLM prompt.  The mapping rules inspect raw numeric/categorical fields
    from the NSL-KDD feature set and apply simple threshold-based heuristics
    that a SOC analyst would recognise.  This means:

      • Results are reproducible and explainable.
      • No training data or model weights are required.
      • The LLM in the triage pipeline is NOT asked to guess technique IDs
        (LLMs are unreliable at precise taxonomy lookups).

    A viva panel should be told: "The ATT&CK tagging is rule-based, not
    learned.  We chose this because technique IDs must map to a fixed
    taxonomy — a deterministic lookup is more trustworthy than asking an
    LLM to guess the correct T-code."

Coverage:
    Only techniques relevant to network intrusion detection on NSL-KDD
    features are mapped.  This is NOT an attempt to cover the full ATT&CK
    matrix.

References:
    MITRE ATT&CK® — https://attack.mitre.org/
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# ATT&CK Technique Definitions
# ---------------------------------------------------------------------------

class AttackTechnique:
    """A single MITRE ATT&CK technique with its matching rule."""

    __slots__ = ("technique_id", "technique_name", "description", "_match_fn")

    def __init__(
        self,
        technique_id: str,
        technique_name: str,
        description: str,
        match_fn: Any,
    ) -> None:
        self.technique_id = technique_id
        self.technique_name = technique_name
        self.description = description
        self._match_fn = match_fn

    def matches(self, event: dict[str, Any]) -> bool:
        """Return True if *event* triggers this technique's rule."""
        try:
            return bool(self._match_fn(event))
        except (KeyError, TypeError, ValueError):
            return False

    def to_dict(self) -> dict[str, str]:
        return {"id": self.technique_id, "name": self.technique_name}


# ---------------------------------------------------------------------------
# Helper: safe numeric accessor
# ---------------------------------------------------------------------------

def _num(event: dict, key: str, default: float = 0.0) -> float:
    """Get a numeric value from *event*, returning *default* on failure."""
    try:
        return float(event.get(key, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Technique Lookup Table  (5-8 rules as specified)
# ---------------------------------------------------------------------------

ATTACK_TECHNIQUES: list[AttackTechnique] = [

    # 1. C2 Communication — high connection count to a single service,
    #    steady traffic pattern (same_srv_rate close to 1).
    AttackTechnique(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        description=(
            "Rapid repeated connections to one service (high count + high "
            "same_srv_rate) suggest command-and-control communication over "
            "application-layer protocols."
        ),
        match_fn=lambda e: (
            _num(e, "count") > 200
            and _num(e, "same_srv_rate") > 0.85
            and _num(e, "dst_host_same_srv_rate") > 0.85
        ),
    ),

    # 2. Port Scan — many distinct destination ports, short durations.
    AttackTechnique(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        description=(
            "High diff_srv_rate with low duration and many connections "
            "indicates port-scanning behaviour (probing many services)."
        ),
        match_fn=lambda e: (
            _num(e, "diff_srv_rate") > 0.50
            and _num(e, "dst_host_diff_srv_rate") > 0.30
            and _num(e, "duration") < 2
            and _num(e, "count") > 10
        ),
    ),

    # 3. Brute Force — multiple failed login attempts.
    AttackTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        description=(
            "Elevated num_failed_logins indicates credential-guessing / "
            "brute-force authentication attempts."
        ),
        match_fn=lambda e: (
            _num(e, "num_failed_logins") >= 3
        ),
    ),

    # 4. Exfiltration Over C2 Channel — large outbound data volume.
    AttackTechnique(
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        description=(
            "Very high src_bytes with relatively low dst_bytes suggests "
            "large data being sent outbound (exfiltration)."
        ),
        match_fn=lambda e: (
            _num(e, "src_bytes") > 10_000
            and _num(e, "dst_bytes") < 1_000
            and _num(e, "src_bytes") > 10 * max(_num(e, "dst_bytes"), 1)
        ),
    ),

    # 5. SYN Flood / Connection Reset Storm — high SYN-error rate.
    AttackTechnique(
        technique_id="T1498",
        technique_name="Network Denial of Service",
        description=(
            "High serror_rate (SYN-error rate) across many connections "
            "indicates a SYN-flood or connection-reset denial-of-service."
        ),
        match_fn=lambda e: (
            _num(e, "serror_rate") > 0.70
            and _num(e, "count") > 50
        ),
    ),

    # 6. Privilege Escalation — root shell or su attempt.
    AttackTechnique(
        technique_id="T1068",
        technique_name="Exploitation for Privilege Escalation",
        description=(
            "root_shell or su_attempted flags indicate an attempt to "
            "escalate privileges on the target host."
        ),
        match_fn=lambda e: (
            _num(e, "root_shell") >= 1
            or _num(e, "su_attempted") >= 1
        ),
    ),

    # 7. Lateral Movement / Remote Services — logged in + host compromise
    #    indicators across many hosts.
    AttackTechnique(
        technique_id="T1021",
        technique_name="Remote Services",
        description=(
            "Logged-in session with compromised-host indicators and high "
            "dst_host_srv_diff_host_rate suggests lateral movement across "
            "internal hosts via remote services."
        ),
        match_fn=lambda e: (
            _num(e, "logged_in") >= 1
            and _num(e, "num_compromised") >= 1
            and _num(e, "dst_host_srv_diff_host_rate") > 0.40
        ),
    ),

    # 8. Connection Reset Abuse — high REJ-flag error rate.
    AttackTechnique(
        technique_id="T1095",
        technique_name="Non-Application Layer Protocol",
        description=(
            "High rerror_rate (connection-reset/rejection rate) with many "
            "connections suggests abuse of non-application-layer protocols "
            "(e.g., raw TCP RST floods)."
        ),
        match_fn=lambda e: (
            _num(e, "rerror_rate") > 0.70
            and _num(e, "count") > 30
        ),
    ),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_attack_techniques(raw_event: dict[str, Any]) -> list[dict[str, str]]:
    """Match a raw NSL-KDD event against the ATT&CK lookup table.

    Parameters
    ----------
    raw_event : dict
        The 41-feature NSL-KDD event dictionary.

    Returns
    -------
    list[dict]
        Each match is ``{"id": "Txxxx", "name": "Technique Name"}``.
        Returns an empty list when no rules fire.
    """
    matched: list[dict[str, str]] = []
    for technique in ATTACK_TECHNIQUES:
        if technique.matches(raw_event):
            matched.append(technique.to_dict())
    return matched
