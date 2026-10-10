#!/usr/bin/env python3
"""
convert_arff_to_csv.py
-----------------------
Converts Weka .arff dataset files (e.g. NSL-KDD, KDDTrain+, KDDTest+)
into clean, flat .csv files with standard header rows.

Correctly handles ARFF's @ATTRIBUTE header declarations (including
quoted attribute names and nominal type sets) and data rows with
quoted values or embedded commas (both single and double quotes).

USAGE
-----
    python convert_arff_to_csv.py --input KDDTrain+.arff --output KDDTrain+.csv
    python convert_arff_to_csv.py --input-dir ml/data/raw/nsl_kdd --output-dir data/csv
"""

from __future__ import annotations

import argparse
import csv
import io
import os
import sys
from pathlib import Path
from typing import Iterator


def parse_arff_attributes(lines_iter: Iterator[str]) -> list[str]:
    """Parse @attribute lines from an ARFF file and return the list of attribute names."""
    attributes: list[str] = []

    for line in lines_iter:
        stripped = line.strip()
        if not stripped or stripped.startswith("%"):
            continue

        lower = stripped.lower()
        if lower.startswith("@attribute"):
            content = stripped[len("@attribute"):].strip()
            if not content:
                continue

            if content.startswith("'"):
                end_quote = content.find("'", 1)
                attr_name = content[1:end_quote] if end_quote != -1 else content.split()[0].strip("'\"")
            elif content.startswith('"'):
                end_quote = content.find('"', 1)
                attr_name = content[1:end_quote] if end_quote != -1 else content.split()[0].strip("'\"")
            else:
                attr_name = content.split()[0]

            attributes.append(attr_name)

        elif lower.startswith("@data"):
            break

    return attributes


def parse_arff_data_line(line: str) -> list[str]:
    """Parse a single ARFF data row, respecting single and double quotes with embedded commas."""
    line = line.strip()
    if not line or line.startswith("%"):
        return []

    # Fast path for rows without quotes
    if "'" not in line and '"' not in line:
        return [val.strip() for val in line.split(",")]

    tokens: list[str] = []
    current: list[str] = []
    in_quote: str | None = None
    escaped = False

    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif in_quote is not None:
            if char == in_quote:
                in_quote = None
            else:
                current.append(char)
        else:
            if char in ("'", '"'):
                in_quote = char
            elif char == ",":
                tokens.append("".join(current).strip())
                current = []
            else:
                current.append(char)

    tokens.append("".join(current).strip())
    return tokens


def convert_arff_to_csv(
    arff_path: str | Path,
    csv_path: str | Path,
    encoding: str = "utf-8",
) -> int:
    """Convert a single .arff file into a clean, flat .csv file.

    Parameters
    ----------
    arff_path : str | Path
        Path to the input .arff file.
    csv_path : str | Path
        Path to write the resulting .csv file.
    encoding : str
        Character encoding to use (default: utf-8).

    Returns
    -------
    int
        Number of data rows converted.
    """
    arff_path = Path(arff_path)
    csv_path = Path(csv_path)

    if not arff_path.exists():
        raise FileNotFoundError(f"Input ARFF file not found: {arff_path}")

    csv_path.parent.mkdir(parents=True, exist_ok=True)

    with open(arff_path, "r", encoding=encoding, errors="replace") as in_fh:
        # 1. Parse attributes from header
        attributes = parse_arff_attributes(in_fh)

        if not attributes:
            raise ValueError(f"No @attribute declarations found in {arff_path}")

        # 2. Stream and write data rows directly to CSV
        rows_written = 0
        with open(csv_path, "w", encoding="utf-8", newline="") as out_fh:
            writer = csv.writer(out_fh, quoting=csv.QUOTE_MINIMAL)
            # Write header
            writer.writerow(attributes)

            # Read remaining lines as CSV data rows
            for line in in_fh:
                row = parse_arff_data_line(line)
                if row:
                    writer.writerow(row)
                    rows_written += 1

    return rows_written


def batch_convert(
    input_dir: str | Path,
    output_dir: str | Path,
    pattern: str = "*.arff",
) -> dict[str, int]:
    """Convert all ARFF files matching pattern in input_dir to CSV in output_dir."""
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, int] = {}
    arff_files = sorted(input_dir.glob(pattern))

    for arff_file in arff_files:
        csv_file = output_dir / f"{arff_file.stem}.csv"
        print(f"  Converting {arff_file.name} -> {csv_file.name} ...", end=" ", flush=True)
        count = convert_arff_to_csv(arff_file, csv_file)
        print(f"Done ({count:,} rows)")
        results[arff_file.name] = count

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Weka .arff dataset files to clean .csv files."
    )
    parser.add_argument("--input", "-i", type=str, help="Input ARFF file path")
    parser.add_argument("--output", "-o", type=str, help="Output CSV file path")
    parser.add_argument("--input-dir", type=str, help="Input directory containing ARFF files")
    parser.add_argument("--output-dir", type=str, default="data/csv", help="Output directory for CSV files")

    args = parser.parse_args()

    if args.input:
        out = args.output or str(Path(args.output_dir) / f"{Path(args.input).stem}.csv")
        print(f"Converting {args.input} -> {out} ...")
        count = convert_arff_to_csv(args.input, out)
        print(f"Success: {count:,} rows converted.")
    elif args.input_dir:
        print(f"Batch converting ARFF files in {args.input_dir} -> {args.output_dir} ...")
        results = batch_convert(args.input_dir, args.output_dir)
        print(f"Total files converted: {len(results)}")
    else:
        # Default behavior: convert project NSL-KDD raw files to data/csv/
        project_root = Path(__file__).resolve().parent.parent
        if project_root.name == "scripts":
            project_root = project_root.parent
        raw_dir = project_root / "ml" / "data" / "raw" / "nsl_kdd"
        out_dir = project_root / "data" / "csv"
        if raw_dir.exists():
            print(f"Converting project ARFF datasets from {raw_dir} -> {out_dir} ...")
            results = batch_convert(raw_dir, out_dir)
            print("Batch conversion complete.")
        else:
            parser.print_help()


if __name__ == "__main__":
    main()
