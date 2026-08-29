"""CLI test script — runs one hardcoded dummy event through the full
SentinelAI agent pipeline and prints each node's output clearly labeled.

Usage:
    python test_pipeline.py
"""

from __future__ import annotations

import json
import sys

from pipeline import AlertState, build_graph


# ---------------------------------------------------------------------------
# Hardcoded dummy network event
# ---------------------------------------------------------------------------

DUMMY_EVENT: dict[str, str | int | float] = {
    "src_ip": "192.168.1.105",
    "dst_ip": "10.0.0.3",
    "protocol": "TCP",
    "src_port": 44821,
    "dst_port": 443,
    "bytes_sent": 1_240_000,
    "bytes_received": 350,
    "duration_seconds": 2.4,
    "flag": "SYN",
    "packet_count": 8500,
}


def main() -> None:
    """Execute the full triage -> severity -> response pipeline."""
    print("+" + "=" * 58 + "+")
    print("|   SentinelAI -- Agent Pipeline Test Run" + " " * 18 + "|")
    print("+" + "=" * 58 + "+")
    print()
    print("Input event:")
    print(json.dumps(DUMMY_EVENT, indent=2))
    print()

    # Build graph
    try:
        pipeline = build_graph()
    except EnvironmentError as exc:
        print(f"\n❌ Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Run the pipeline
    initial_state: AlertState = {
        "alert": DUMMY_EVENT,
        "triage_explanation": "",
        "severity_level": "",
        "severity_justification": "",
        "response_action": "",
        "error": "",
    }

    try:
        result = pipeline.invoke(initial_state)
    except Exception as exc:
        print(f"\n❌ Pipeline execution failed: {exc}", file=sys.stderr)
        sys.exit(1)

    # Summary
    print()
    print("+" + "=" * 58 + "+")
    print("|   PIPELINE SUMMARY" + " " * 39 + "|")
    print("+" + "=" * 58 + "+")
    print(f"  Triage   : {result.get('triage_explanation', 'N/A')[:120]}...")
    print(f"  Severity : {result.get('severity_level', 'N/A')}")
    print(f"  Reason   : {result.get('severity_justification', 'N/A')}")
    print(f"  Action   : {result.get('response_action', 'N/A')}")

    if result.get("error"):
        print(f"\n[WARN] Errors encountered: {result['error']}")


if __name__ == "__main__":
    main()
