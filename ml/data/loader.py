"""NSL-KDD dataset loader and preprocessor.

Loads clean, flat CSV files from /data/csv/ (converted from .arff),
encodes categoricals, scales numerics, and saves processed splits
for downstream model training. Retains ARFF parsing capability for
backward compatibility and initial conversions.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent.parent
_CSV_DIR = _PROJECT_ROOT / "data" / "csv"
_RAW_DIR = _THIS_DIR / "raw" / "nsl_kdd"
_PROCESSED_DIR = _THIS_DIR / "processed"

# CSV dataset paths (primary, fast, flat format)
_TRAIN_FULL_CSV = _CSV_DIR / "KDDTrain+.csv"
_TRAIN_20_CSV = _CSV_DIR / "KDDTrain+_20Percent.csv"
_TEST_CSV = _CSV_DIR / "KDDTest+.csv"

# ARFF dataset paths (raw historical archive)
_TRAIN_FULL_ARFF = _RAW_DIR / "KDDTrain+.arff"
_TRAIN_20_ARFF = _RAW_DIR / "KDDTrain+_20Percent.arff"
_TEST_ARFF = _RAW_DIR / "KDDTest+.arff"

# Default aliases for backward compatibility
_TRAIN_FULL = _TRAIN_FULL_CSV if _TRAIN_FULL_CSV.exists() else _TRAIN_FULL_ARFF
_TRAIN_20 = _TRAIN_20_CSV if _TRAIN_20_CSV.exists() else _TRAIN_20_ARFF
_TEST = _TEST_CSV if _TEST_CSV.exists() else _TEST_ARFF

# The three categorical columns in the NSL-KDD dataset
CATEGORICAL_COLS: list[str] = ["protocol_type", "service", "flag"]


# ---------------------------------------------------------------------------
# 1. load_csv
# ---------------------------------------------------------------------------

def load_csv(filepath: str | Path) -> pd.DataFrame:
    """Load a dataset from a clean CSV file into a pandas DataFrame.

    Ensures numeric features are properly cast to float types and categoricals
    are preserved as strings.

    Returns
    -------
    pd.DataFrame
        DataFrame with 42 columns (41 features + 'class').
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"CSV file not found: {filepath}")

    df = pd.read_csv(filepath)

    # Convert numeric columns to float (everything except categoricals and class)
    for col in df.columns:
        if col not in CATEGORICAL_COLS and col != "class":
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


# ---------------------------------------------------------------------------
# 2. load_arff (Retained for ARFF handling and backwards compatibility)
# ---------------------------------------------------------------------------

def load_arff(filepath: str | Path) -> pd.DataFrame:
    """Parse a single .arff file into a pandas DataFrame.

    Reads @attribute lines to get column names, then reads CSV rows after
    the @data marker. This avoids scipy.io.arff which fails on the
    malformed nominal declaration for ``protocol_type``.

    Returns
    -------
    pd.DataFrame
        DataFrame with 42 columns (41 features + 'class').
    """
    filepath = Path(filepath)
    # If a corresponding .csv already exists, prefer the fast CSV path
    csv_equivalent = _CSV_DIR / f"{filepath.stem}.csv"
    if csv_equivalent.exists():
        return load_csv(csv_equivalent)

    col_names: list[str] = []
    data_start_idx: int = -1

    with open(filepath, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    # Pass 1 — extract column names from @attribute lines
    for idx, line in enumerate(lines):
        stripped = line.strip()
        lower = stripped.lower()

        if lower.startswith("@attribute"):
            rest = stripped[len("@attribute"):].strip()
            if rest.startswith("'"):
                end_quote = rest.index("'", 1)
                name = rest[1:end_quote]
            elif rest.startswith('"'):
                end_quote = rest.index('"', 1)
                name = rest[1:end_quote]
            else:
                name = rest.split()[0]
            col_names.append(name)

        elif lower.startswith("@data"):
            data_start_idx = idx + 1
            break

    if data_start_idx < 0:
        raise ValueError(f"No @data marker found in {filepath}")
    if len(col_names) != 42:
        raise ValueError(
            f"Expected 42 columns but parsed {len(col_names)} from {filepath}"
        )

    # Pass 2 — read CSV data rows
    data_rows: list[list[str]] = []
    for line in lines[data_start_idx:]:
        stripped = line.strip()
        if stripped and not stripped.startswith("%"):
            data_rows.append(stripped.split(","))

    df = pd.DataFrame(data_rows, columns=col_names)

    # Convert numeric columns to float (everything except categoricals and class)
    for col in df.columns:
        if col not in CATEGORICAL_COLS and col != "class":
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def load_dataset(filepath: str | Path) -> pd.DataFrame:
    """Load either a .csv or .arff dataset file automatically based on extension."""
    filepath = Path(filepath)
    if filepath.suffix.lower() == ".csv":
        return load_csv(filepath)
    return load_arff(filepath)


# ---------------------------------------------------------------------------
# 3. load_nsl_kdd
# ---------------------------------------------------------------------------

def load_nsl_kdd(
    use_20_percent: bool = False,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load NSL-KDD train and test sets as DataFrames from clean CSV files.

    If CSV files are available in data/csv/, loads them instantly.
    Falls back to .arff files if CSVs have not been generated yet.

    Parameters
    ----------
    use_20_percent : bool
        If True, load the smaller 20% training subset (faster iteration).

    Returns
    -------
    (train_df, test_df)
        Two DataFrames with original string values, no encoding applied.
    """
    train_csv = _TRAIN_20_CSV if use_20_percent else _TRAIN_FULL_CSV
    test_csv = _TEST_CSV

    if train_csv.exists() and test_csv.exists():
        return load_csv(train_csv), load_csv(test_csv)

    # Fallback to ARFF
    train_arff = _TRAIN_20_ARFF if use_20_percent else _TRAIN_FULL_ARFF
    test_arff = _TEST_ARFF

    if not train_arff.exists():
        raise FileNotFoundError(f"Training file not found: {train_arff} or {train_csv}")
    if not test_arff.exists():
        raise FileNotFoundError(f"Test file not found: {test_arff} or {test_csv}")

    train_df = load_arff(train_arff)
    test_df = load_arff(test_arff)

    return train_df, test_df


# ---------------------------------------------------------------------------
# 4. preprocess
# ---------------------------------------------------------------------------

def preprocess(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    save: bool = True,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Encode, scale, and split into numpy arrays.

    - OneHotEncoder (fit on train only, handle_unknown='ignore') for
      protocol_type, service, flag.
    - StandardScaler (fit on train only) for all numeric features.
    - Class label: 'normal' -> 0, everything else (anomaly) -> 1.

    Parameters
    ----------
    train_df, test_df : pd.DataFrame
        Raw DataFrames from ``load_nsl_kdd``.
    save : bool
        If True, persist processed arrays and fitted transformers to
        ``ml/data/processed/``.

    Returns
    -------
    (X_train, y_train, X_test, y_test)
        All as numpy arrays. X arrays are float64, y arrays are int64.
    """
    # --- Labels -----------------------------------------------------------
    y_train = (train_df["class"] != "normal").astype(np.int64).values
    y_test = (test_df["class"] != "normal").astype(np.int64).values

    # --- Feature matrices (drop class column) -----------------------------
    train_feats = train_df.drop(columns=["class"])
    test_feats = test_df.drop(columns=["class"])

    # --- Numeric columns --------------------------------------------------
    numeric_cols = [c for c in train_feats.columns if c not in CATEGORICAL_COLS]

    scaler = StandardScaler()
    train_numeric = scaler.fit_transform(
        train_feats[numeric_cols].values.astype(np.float64)
    )
    test_numeric = scaler.transform(
        test_feats[numeric_cols].values.astype(np.float64)
    )

    # --- Categorical columns (OneHot, fit on train only) ------------------
    encoder = OneHotEncoder(
        sparse_output=False,
        handle_unknown="ignore",   # test has categories unseen in train
        dtype=np.float64,
    )
    train_cat = encoder.fit_transform(train_feats[CATEGORICAL_COLS])
    test_cat = encoder.transform(test_feats[CATEGORICAL_COLS])

    # --- Combine numeric + one-hot ----------------------------------------
    X_train = np.hstack([train_numeric, train_cat])
    X_test = np.hstack([test_numeric, test_cat])

    # --- Hard check: column counts must match -----------------------------
    if X_train.shape[1] != X_test.shape[1]:
        raise ValueError(
            f"Column count mismatch after encoding! "
            f"X_train has {X_train.shape[1]} cols, "
            f"X_test has {X_test.shape[1]} cols."
        )

    # --- Save artifacts ---------------------------------------------------
    if save:
        _PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

        np.save(_PROCESSED_DIR / "train_X.npy", X_train)
        np.save(_PROCESSED_DIR / "train_y.npy", y_train)
        np.save(_PROCESSED_DIR / "test_X.npy", X_test)
        np.save(_PROCESSED_DIR / "test_y.npy", y_test)

        joblib.dump(scaler, _PROCESSED_DIR / "scaler.joblib")
        joblib.dump(encoder, _PROCESSED_DIR / "encoder.joblib")

        print(f"  Saved processed arrays to {_PROCESSED_DIR}")
        print(f"  Saved scaler  -> scaler.joblib")
        print(f"  Saved encoder -> encoder.joblib")

    return X_train, y_train, X_test, y_test
