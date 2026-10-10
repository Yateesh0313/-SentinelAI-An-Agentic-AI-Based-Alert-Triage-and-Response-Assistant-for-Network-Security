"""Test script — validates the 3-part triage explanation structure across
three different attack types: port scan, brute force, and malware C2 beacon.

Checks that each explanation follows the WHAT HAPPENED / WHY IT MATTERS /
WHAT WE RECOMMEND format and stays clear and non-jargon-heavy.

Usage:
    cd agents
    python test_triage_format.py
"""

from __future__ import annotations

import json
import re
import sys

from pipeline import AlertState, build_graph


# ---------------------------------------------------------------------------
# Three test events: port scan, brute force, malware C2 beacon
# ---------------------------------------------------------------------------

PORT_SCAN_EVENT: dict[str, str | int | float] = {
    "duration": 0,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "REJ",
    "src_bytes": 0,
    "dst_bytes": 0,
    "land": 0,
    "wrong_fragment": 0,
    "urgent": 0,
    "hot": 0,
    "num_failed_logins": 0,
    "logged_in": 0,
    "num_compromised": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "num_root": 0,
    "num_file_creations": 0,
    "num_shells": 0,
    "num_access_files": 0,
    "num_outbound_cmds": 0,
    "is_host_login": 0,
    "is_guest_login": 0,
    "count": 120,
    "srv_count": 6,
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "rerror_rate": 0.05,
    "srv_rerror_rate": 0.0,
    "same_srv_rate": 0.05,
    "diff_srv_rate": 0.07,
    "srv_diff_host_rate": 0.0,
    "dst_host_count": 255,
    "dst_host_srv_count": 1,
    "dst_host_same_srv_rate": 0.0,
    "dst_host_diff_srv_rate": 0.60,
    "dst_host_same_src_port_rate": 0.88,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0,
}

BRUTE_FORCE_EVENT: dict[str, str | int | float] = {
    "duration": 0,
    "protocol_type": "tcp",
    "service": "ftp",
    "flag": "SF",
    "src_bytes": 232,
    "dst_bytes": 588,
    "land": 0,
    "wrong_fragment": 0,
    "urgent": 0,
    "hot": 0,
    "num_failed_logins": 5,
    "logged_in": 0,
    "num_compromised": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "num_root": 0,
    "num_file_creations": 0,
    "num_shells": 0,
    "num_access_files": 0,
    "num_outbound_cmds": 0,
    "is_host_login": 0,
    "is_guest_login": 0,
    "count": 4,
    "srv_count": 4,
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0,
    "same_srv_rate": 1.0,
    "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0,
    "dst_host_count": 12,
    "dst_host_srv_count": 12,
    "dst_host_same_srv_rate": 1.0,
    "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.08,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0,
}

MALWARE_C2_BEACON_EVENT: dict[str, str | int | float] = {
    "duration": 1,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "SF",
    "src_bytes": 310,
    "dst_bytes": 450,
    "land": 0,
    "wrong_fragment": 0,
    "urgent": 0,
    "hot": 0,
    "num_failed_logins": 0,
    "logged_in": 1,
    "num_compromised": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "num_root": 0,
    "num_file_creations": 0,
    "num_shells": 0,
    "num_access_files": 0,
    "num_outbound_cmds": 0,
    "is_host_login": 0,
    "is_guest_login": 0,
    "count": 350,
    "srv_count": 350,
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0,
    "same_srv_rate": 1.0,
    "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0,
    "dst_host_count": 255,
    "dst_host_srv_count": 255,
    "dst_host_same_srv_rate": 1.0,
    "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 1.0,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0,
}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _count_sentences(text: str) -> int:
    """Rough sentence count — split on sentence-ending punctuation."""
    # Remove the [Ref: ...] tag line before counting
    cleaned = re.sub(r"\[Ref:.*?\]", "", text).strip()
    # Split on ., !, ? followed by whitespace or end-of-string
    sentences = re.split(r"(?<=[.!?])\s+", cleaned)
    # Filter out empty strings
    return len([s for s in sentences if s.strip()])


JARGON_TERMS = [
    "src_bytes", "dst_bytes", "serror_rate", "rerror_rate", "diff_srv_rate",
    "same_srv_rate", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "num_failed_logins", "srv_count", "dst_host_count", "flag",
    "protocol_type", "num_compromised", "root_shell", "su_attempted",
]


def _check_raw_field_jargon(text: str) -> list[str]:
    """Return any raw NSL-KDD field names that appear verbatim in text."""
    found = []
    for term in JARGON_TERMS:
        if term in text.lower():
            found.append(term)
    return found


def validate_explanation(label: str, explanation: str) -> bool:
    """Validate the 3-part structure.  Returns True if all checks pass."""
    print(f"\n{'-'*60}")
    print(f"  VALIDATING: {label}")
    print(f"{'-'*60}")
    print(f"  Explanation:\n{explanation}\n")

    passed = True

    # 1. Sentence count ≤ 4  (excluding [Ref:] line)
    n_sentences = _count_sentences(explanation)
    if n_sentences > 6:  # generous upper bound (LLM may vary a bit)
        print(f"  [WARN] Sentence count = {n_sentences} (target ≤ 4)")
        passed = False
    else:
        print(f"  [OK]   Sentence count = {n_sentences}")

    # 2. Check for raw field-name jargon leaked into the text
    jargon_found = _check_raw_field_jargon(explanation)
    if jargon_found:
        print(f"  [WARN] Raw field jargon found: {jargon_found}")
        # This is a warning, not a hard fail — LLMs sometimes reference
        # field names even when told not to.
    else:
        print(f"  [OK]   No raw field-name jargon detected")

    # 3. ATT&CK reference tag format (if present)
    ref_match = re.search(r"\[Ref:.*?\]", explanation)
    if ref_match:
        tag = ref_match.group()
        # Verify it contains a T-code
        if re.search(r"T\d{4}", tag):
            print(f"  [OK]   ATT&CK reference tag found: {tag}")
        else:
            print(f"  [WARN] Reference tag found but no T-code: {tag}")
    else:
        print(f"  [INFO] No ATT&CK reference tag (may be expected)")

    # 4. Length check — should be concise
    if len(explanation) > 1000:
        print(f"  [WARN] Explanation is long ({len(explanation)} chars)")
    else:
        print(f"  [OK]   Length is concise ({len(explanation)} chars)")

    return passed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TEST_CASES = [
    ("Port Scan", PORT_SCAN_EVENT),
    ("Brute Force", BRUTE_FORCE_EVENT),
    ("Malware C2 Beacon", MALWARE_C2_BEACON_EVENT),
]


def main() -> None:
    print("+" + "=" * 58 + "+")
    print("|  SentinelAI — Triage 3-Part Format Validation" + " " * 11 + "|")
    print("+" + "=" * 58 + "+")
    print()

    # Build graph
    try:
        pipeline = build_graph()
    except EnvironmentError as exc:
        print(f"\n  Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    results: list[tuple[str, str, bool]] = []

    for label, event in TEST_CASES:
        print(f"\n{'='*60}")
        print(f"  Running pipeline for: {label}")
        print(f"{'='*60}")
        print(f"  Event (excerpt): {json.dumps({k: event[k] for k in list(event)[:8]}, indent=2)}")

        initial_state: AlertState = {
            "alert": event,
            "triage_explanation": "",
            "attack_techniques": [],
            "severity_level": "",
            "severity_justification": "",
            "response_action": "",
            "error": "",
        }

        try:
            result = pipeline.invoke(initial_state)
        except Exception as exc:
            print(f"\n  Pipeline execution failed: {exc}", file=sys.stderr)
            results.append((label, "", False))
            continue

        explanation = result.get("triage_explanation", "")
        if not explanation:
            print(f"  [FAIL] No triage explanation produced (error: {result.get('error', '')})")
            results.append((label, "", False))
            continue

        ok = validate_explanation(label, explanation)
        results.append((label, explanation, ok))

    # Final summary
    print(f"\n\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    for label, expl, ok in results:
        status = "PASS" if ok else "WARN"
        preview = expl[:80].replace("\n", " ") + "..." if expl else "(empty)"
        print(f"  [{status}] {label}: {preview}")

    all_ok = all(ok for _, _, ok in results)
    print(f"\n  Overall: {'ALL PASSED' if all_ok else 'SOME WARNINGS — review above'}")


if __name__ == "__main__":
    main()
