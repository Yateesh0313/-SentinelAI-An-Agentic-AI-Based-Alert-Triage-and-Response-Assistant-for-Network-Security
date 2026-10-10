"""Unit tests for convert_arff_to_csv.py."""

from __future__ import annotations

import io
import sys
from pathlib import Path
import pandas as pd
import pytest

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "backend" / "scripts"))
sys.path.insert(0, str(_PROJECT_ROOT / "scripts"))

from convert_arff_to_csv import convert_arff_to_csv, parse_arff_attributes


def test_parse_arff_attributes():
    """Verify attribute parsing handles quotes, nominal sets, and standard types."""
    sample_header = """
    % Sample comment line
    @relation test_net
    @attribute duration real
    @attribute 'protocol_type' {'tcp','udp','icmp'}
    @attribute "service" string
    @attribute 'flag with space' {'SF', 'S0', 'REJ'}
    @attribute src_bytes numeric
    @data
    0,tcp,http,SF,100
    """
    lines = io.StringIO(sample_header.strip())
    attributes = parse_arff_attributes(lines)

    assert attributes == [
        "duration",
        "protocol_type",
        "service",
        "flag with space",
        "src_bytes",
    ]


def test_convert_arff_to_csv_quoted_values_with_commas(tmp_path: Path):
    """Verify data rows with quoted values and embedded commas are parsed correctly."""
    arff_content = """
    % Comment line
    @relation complex_data
    @attribute id numeric
    @attribute description string
    @attribute tag string
    @data
    1,"Connection established, high latency",critical
    2,"Normal web traffic, port 80",normal
    3,'Single quotes, also with comma',warning
    """
    arff_file = tmp_path / "test.arff"
    csv_file = tmp_path / "test.csv"

    arff_file.write_text(arff_content.strip(), encoding="utf-8")

    rows = convert_arff_to_csv(arff_file, csv_file)
    assert rows == 3
    assert csv_file.exists()

    df = pd.read_csv(csv_file)
    assert list(df.columns) == ["id", "description", "tag"]
    assert len(df) == 3
    assert df.iloc[0]["description"] == "Connection established, high latency"
    assert df.iloc[1]["description"] == "Normal web traffic, port 80"
    assert df.iloc[2]["description"] == "Single quotes, also with comma"


def test_convert_project_kdd_subset(tmp_path: Path):
    """Test on real NSL-KDD raw subset."""
    raw_arff = _PROJECT_ROOT / "ml" / "data" / "raw" / "nsl_kdd" / "KDDTrain+_20Percent.arff"
    if not raw_arff.exists():
        pytest.skip("KDDTrain+_20Percent.arff not found")

    out_csv = tmp_path / "kdd_subset.csv"
    count = convert_arff_to_csv(raw_arff, out_csv)

    assert count == 25192
    df = pd.read_csv(out_csv)
    assert df.shape == (25192, 42)
    assert "protocol_type" in df.columns
    assert "class" in df.columns
