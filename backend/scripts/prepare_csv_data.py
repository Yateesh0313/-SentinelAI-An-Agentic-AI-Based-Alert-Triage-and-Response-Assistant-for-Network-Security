#!/usr/bin/env python3
"""
scripts/prepare_csv_data.py
----------------------------
One-time setup / data-prep step that converts all existing .arff dataset files
in the project (NSL-KDD train and test sets) into clean, flat .csv files
using convert_arff_to_csv.py.

Target output directory: /data/csv/
  - data/csv/KDDTrain+.csv
  - data/csv/KDDTrain+_20Percent.csv
  - data/csv/KDDTest+.csv
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Add backend/scripts and scripts to sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
for p in [_PROJECT_ROOT / "backend" / "scripts", _PROJECT_ROOT / "scripts"]:
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from convert_arff_to_csv import convert_arff_to_csv


def prepare_all_csv_datasets() -> dict[str, Path]:
    """Convert all existing NSL-KDD .arff files to .csv in data/csv/."""
    raw_arff_dir = _PROJECT_ROOT / "ml" / "data" / "raw" / "nsl_kdd"
    csv_dir = _PROJECT_ROOT / "data" / "csv"
    csv_dir.mkdir(parents=True, exist_ok=True)

    datasets = [
        "KDDTrain+.arff",
        "KDDTrain+_20Percent.arff",
        "KDDTest+.arff",
    ]

    print("=" * 68)
    print("  SentinelAI -- One-Time Dataset ARFF -> CSV Data Preparation")
    print("=" * 68)
    print(f"  Source directory : {raw_arff_dir}")
    print(f"  Target directory : {csv_dir}")
    print("-" * 68)

    converted: dict[str, Path] = {}
    t0 = time.time()

    for filename in datasets:
        in_path = raw_arff_dir / filename
        out_name = f"{in_path.stem}.csv"
        out_path = csv_dir / out_name

        if not in_path.exists():
            print(f"  [MISSING] {in_path.name} not found in {raw_arff_dir}")
            continue

        print(f"  Converting {in_path.name} -> {out_name} ...", end=" ", flush=True)
        t_file = time.time()
        try:
            count = convert_arff_to_csv(in_path, out_path)
            size_mb = out_path.stat().st_size / (1024 * 1024)
            elapsed = time.time() - t_file
            print(f"DONE ({count:,} rows, {size_mb:.2f} MB in {elapsed:.2f}s)")
            converted[out_name] = out_path
        except Exception as exc:
            print(f"FAILED: {exc}")

    total_time = time.time() - t0
    print("-" * 68)
    print(f"  Completed {len(converted)}/{len(datasets)} dataset conversions in {total_time:.2f}s.")
    print("=" * 68)

    return converted


if __name__ == "__main__":
    prepare_all_csv_datasets()
