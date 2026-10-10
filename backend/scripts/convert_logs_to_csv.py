#!/usr/bin/env python3
"""
convert_logs_to_csv.py
-----------------------
Converts Suricata eve.json (line-delimited JSON) and honeypot log files
(also line-delimited JSON, e.g. Cowrie/Dionaea style) into clean,
flat .csv files that open correctly in Excel / LibreOffice Calc /
Google Sheets.

USAGE
-----
    # Convert Suricata alerts only (recommended for triage/dashboard use)
    python convert_logs_to_csv.py --input eve.json --output suricata_alerts.csv --source suricata --alerts-only

    # Convert ALL Suricata event types (alert, flow, dns, http, etc.)
    python convert_logs_to_csv.py --input eve.json --output suricata_all_events.csv --source suricata

    # Convert honeypot logs (generic flattener, works with most JSON-lines honeypot logs)
    python convert_logs_to_csv.py --input honeypot.json --output honeypot_events.csv --source honeypot
"""

import argparse
import csv
import json
import sys
from pathlib import Path


def flatten_json(obj, parent_key="", sep="_"):
    """
    Recursively flattens a nested dict/list into a single-level dict.
    Example:
        {"alert": {"signature": "ET SCAN", "severity": 2}}
        becomes
        {"alert_signature": "ET SCAN", "alert_severity": 2}
    """
    items = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else str(key)
            items.update(flatten_json(value, new_key, sep=sep))
    elif isinstance(obj, list):
        if all(not isinstance(v, (dict, list)) for v in obj):
            items[parent_key] = "; ".join(str(v) for v in obj)
        else:
            for i, value in enumerate(obj):
                items.update(flatten_json(value, f"{parent_key}{sep}{i}", sep=sep))
    else:
        items[parent_key] = obj
    return items


def load_jsonlines(filepath):
    """
    Reads a line-delimited JSON file (one JSON object per line).
    Skips and reports any malformed lines instead of crashing.
    """
    records = []
    skipped = 0
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1
    if skipped:
        print(f"[!] Skipped {skipped} malformed/incomplete line(s) in {filepath}", file=sys.stderr)
    return records


def convert(input_path, output_path, source, alerts_only):
    records = load_jsonlines(input_path)
    if not records:
        print(f"[!] No valid JSON records found in {input_path}. Nothing to convert.", file=sys.stderr)
        sys.exit(1)

    if source == "suricata" and alerts_only:
        before = len(records)
        records = [r for r in records if r.get("event_type") == "alert"]
        print(f"[i] Filtered to alert events only: {len(records)} of {before} total events kept.")

    flat_rows = [flatten_json(r) for r in records]

    priority_cols = [
        "timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
        "alert_signature", "alert_category", "alert_severity",
        "flow_id", "app_proto",
    ]
    all_cols = set()
    for row in flat_rows:
        all_cols.update(row.keys())

    ordered_cols = [c for c in priority_cols if c in all_cols]
    remaining_cols = sorted(c for c in all_cols if c not in ordered_cols)
    final_columns = ordered_cols + remaining_cols

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=final_columns, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        for row in flat_rows:
            writer.writerow(row)

    print(f"[OK] Wrote {len(flat_rows)} rows and {len(final_columns)} columns to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Convert Suricata/honeypot JSON logs to clean CSV.")
    parser.add_argument("--input", required=True, help="Path to input log file (eve.json or honeypot log)")
    parser.add_argument("--output", required=True, help="Path to output .csv file")
    parser.add_argument("--source", required=True, choices=["suricata", "honeypot"],
                         help="Type of log being converted")
    parser.add_argument("--alerts-only", action="store_true",
                         help="(suricata only) Keep only event_type == 'alert' rows, dropping flow/dns/http noise")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    convert(input_path, args.output, args.source, args.alerts_only)


if __name__ == "__main__":
    main()